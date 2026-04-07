"""Eufy Security Cloud REST API client — pure Python, async."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import aiohttp

from ..const import (
    API_BASE_URL,
    API_CHECK_PUSH_TOKEN_PATH,
    API_CIPHER_PATH,
    API_DEVICE_LIST_PATH,
    API_DSK_KEYS_PATH,
    API_LOGIN_PATH,
    API_REGISTER_PUSH_TOKEN_PATH,
    API_SEND_VERIFY_CODE_PATH,
    API_SET_PARAMS_PATH,
    API_STATION_LIST_PATH,
    API_TRUST_DEVICE_PATH,
    API_APP_VERSION,
    API_MCC,
    API_MNC,
    API_NET_TYPE,
    API_OS_TYPE,
    API_OS_VERSION,
    API_PHONE_MODEL,
    SERVER_PUBLIC_KEY_DEFAULT,
)
from .crypto import (
    ECDHKeyExchange,
    decrypt_api_data,
    encrypt_api_data,
    get_null_terminated_string,
    md5_hex,
    decode_p2p_cloud_ips,
)
from .models import CloudPersistentData, DeviceData, StationData
from .types import DeviceType, GuardMode, ResponseCode

_LOGGER = logging.getLogger(__name__)

# Rate limit: max 5 requests per second
_RATE_LIMIT = 5
_RATE_PERIOD = 1.0


class EufyCloudApiError(Exception):
    """Base exception for cloud API errors."""


class AuthenticationError(EufyCloudApiError):
    """Authentication failed."""


class TwoFactorRequired(EufyCloudApiError):
    """2FA verification code required."""


class CaptchaRequired(EufyCloudApiError):
    """CAPTCHA challenge required."""

    def __init__(self, captcha_id: str, captcha_img: str) -> None:
        super().__init__("CAPTCHA required")
        self.captcha_id = captcha_id
        self.captcha_img = captcha_img


class EufyCloudApi:
    """Async client for the Eufy Security cloud REST API."""

    def __init__(
        self,
        email: str,
        password: str,
        country: str = "US",
        session: aiohttp.ClientSession | None = None,
        persistent_data: CloudPersistentData | None = None,
    ) -> None:
        self._email = email
        self._password = password
        self._country = country.upper()
        self._session = session
        self._owns_session = session is None

        # Persistent state
        self._data = persistent_data or CloudPersistentData()

        # Generate unique per-installation device identifiers
        # (avoids Eufy CAPTCHA from shared fingerprints)
        import hashlib as _hl
        _seed = (self._email + self._data.client_private_key).encode()
        _hash = _hl.sha256(_seed).hexdigest()
        self._openudid = _hash[:16]
        self._device_sn = _hash[16:28]

        # ECDH — reuse persisted key pair (don't regenerate on every login)
        if self._data.client_private_key:
            self._ecdh = ECDHKeyExchange.from_private_key_hex(self._data.client_private_key)
        else:
            self._ecdh = ECDHKeyExchange()
            self._data.client_private_key = self._ecdh.private_key_hex

        # Shared secret (AES key)
        server_pub = self._data.server_public_key or SERVER_PUBLIC_KEY_DEFAULT
        self._shared_key = self._ecdh.compute_shared_secret(server_pub)

        # API base URL
        self._api_base = self._data.api_base or ""

        # Auth
        self._auth_token = self._data.auth_token
        self._token_expires = self._data.token_expires_at
        self._user_id = self._data.user_id

        # Rate limiting
        self._rate_semaphore = asyncio.Semaphore(_RATE_LIMIT)
        self._rate_timestamps: list[float] = []

        # Cached data
        self.stations: dict[str, StationData] = {}
        self.devices: dict[str, DeviceData] = {}

    @property
    def persistent_data(self) -> CloudPersistentData:
        """Get current persistent data for session recovery."""
        self._data.auth_token = self._auth_token
        self._data.token_expires_at = self._token_expires
        self._data.user_id = self._user_id
        self._data.api_base = self._api_base
        self._data.server_public_key = self._data.server_public_key or SERVER_PUBLIC_KEY_DEFAULT
        return self._data

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session

    async def close(self) -> None:
        """Close the HTTP session if we own it."""
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    def _headers(self) -> dict[str, str]:
        """Build request headers with unique per-installation device IDs."""
        headers = {
            "App_version": API_APP_VERSION,
            "Os_type": API_OS_TYPE,
            "Os_version": API_OS_VERSION,
            "Phone_model": API_PHONE_MODEL,
            "Country": self._country,
            "Language": "en",
            "Openudid": self._openudid,
            "Net_type": API_NET_TYPE,
            "Mnc": API_MNC,
            "Mcc": API_MCC,
            "Sn": self._device_sn,
            "Model_type": "PHONE",
            "Timezone": "GMT+01:00",
            "Cache-Control": "no-cache",
        }
        if self._auth_token:
            headers["X-Auth-Token"] = self._auth_token
        if self._user_id:
            headers["gtoken"] = md5_hex(self._user_id)
        return headers

    async def _rate_limited_request(
        self, method: str, url: str, **kwargs: Any
    ) -> dict[str, Any]:
        """Make a rate-limited HTTP request."""
        # Simple rate limiting
        now = time.monotonic()
        self._rate_timestamps = [
            t for t in self._rate_timestamps if now - t < _RATE_PERIOD
        ]
        if len(self._rate_timestamps) >= _RATE_LIMIT:
            wait = _RATE_PERIOD - (now - self._rate_timestamps[0])
            if wait > 0:
                await asyncio.sleep(wait)

        session = await self._ensure_session()
        self._rate_timestamps.append(time.monotonic())

        for attempt in range(3):
            try:
                async with session.request(
                    method, url, headers=self._headers(), **kwargs
                ) as resp:
                    if resp.status == 401:
                        _LOGGER.warning("Session expired, re-authenticating")
                        await self.login()
                        continue
                    resp.raise_for_status()
                    return await resp.json()
            except aiohttp.ClientError as err:
                if attempt == 2:
                    raise EufyCloudApiError(f"Request failed: {err}") from err
                await asyncio.sleep(1 * (attempt + 1))

        raise EufyCloudApiError("Max retries exceeded")

    async def _post(self, path: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST to the API."""
        url = f"{self._api_base}/{path}"
        body = data or {}
        body.setdefault("transaction", str(int(time.time() * 1000)))
        result = await self._rate_limited_request("POST", url, json=body)
        code = result.get("code", -1)
        if code != 0:
            _LOGGER.debug("API %s returned code=%s msg=%s", path, code, result.get("msg", ""))
        return result

    async def _get(self, path: str) -> dict[str, Any]:
        """GET from the API."""
        url = f"{self._api_base}/{path}"
        return await self._rate_limited_request("GET", url)

    def _decrypt_response(self, data: Any) -> Any:
        """Decrypt an encrypted response data field."""
        if isinstance(data, str):
            try:
                raw = decrypt_api_data(data, self._shared_key)
                text = get_null_terminated_string(raw)
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    _LOGGER.debug("Decrypted response: %d items", len(parsed))
                else:
                    _LOGGER.debug("Decrypted response: dict")
                return parsed
            except Exception as err:
                _LOGGER.warning("Decrypt failed (%s), trying plain JSON. Data starts with: %s", err, repr(data[:80]) if len(data) > 80 else repr(data))
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    _LOGGER.warning("Not JSON either, returning raw data (%d chars)", len(data))
                    return data
        if isinstance(data, list):
            _LOGGER.debug("Response is already a list with %d items", len(data))
        return data

    # ----- Public API methods -----

    async def discover_api_base(self) -> str:
        """Discover the regional API base URL."""
        session = await self._ensure_session()
        url = f"{API_BASE_URL}/domain/{self._country}"
        async with session.get(url) as resp:
            result = await resp.json()
        if result.get("code") == 0 and "data" in result:
            domain = result["data"].get("domain", "")
            if domain:
                self._api_base = f"https://{domain}"
                self._data.api_base = self._api_base
                self._data.domain = domain
                _LOGGER.debug("Discovered API base: %s", self._api_base)
                return self._api_base
        # Fallback
        self._api_base = "https://security-app.eufylife.com"
        self._data.api_base = self._api_base
        return self._api_base

    async def login(
        self,
        verify_code: str | None = None,
        captcha_id: str | None = None,
        captcha_answer: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate with Eufy cloud.

        Returns the login result data. May raise TwoFactorRequired or
        CaptchaRequired if additional verification is needed.
        """
        if not self._api_base:
            await self.discover_api_base()

        # Reuse the persisted ECDH key pair (like the real Eufy app).
        # Generating new keys on every login triggers CAPTCHA.
        # Use the DEFAULT server public key to encrypt the password.
        login_key = self._ecdh.compute_shared_secret(SERVER_PUBLIC_KEY_DEFAULT)
        encrypted_password = encrypt_api_data(self._password, login_key)

        body: dict[str, Any] = {
            "ab": self._country,
            "client_secret_info": {"public_key": self._ecdh.public_key_hex},
            "enc": 0,
            "email": self._email,
            "password": encrypted_password,
            "time_zone": 3600000,
            "transaction": str(int(time.time() * 1000)),
        }

        if verify_code:
            body["verify_code"] = verify_code
        if captcha_id:
            body["captcha_id"] = captcha_id
        if captcha_answer:
            body["answer"] = captcha_answer

        url = f"{self._api_base}/{API_LOGIN_PATH}"
        session = await self._ensure_session()
        async with session.post(url, headers=self._headers(), json=body) as resp:
            result = await resp.json()

        code = result.get("code", -1)

        if code == ResponseCode.NEED_VERIFY_CODE:
            raise TwoFactorRequired("2FA verification code required")

        if code == ResponseCode.LOGIN_NEED_CAPTCHA:
            data = result.get("data", {})
            raise CaptchaRequired(
                captcha_id=data.get("captcha_id", ""),
                captcha_img=data.get("item", ""),
            )

        if code == ResponseCode.LOGIN_CAPTCHA_ERROR:
            data = result.get("data", {})
            raise CaptchaRequired(
                captcha_id=data.get("captcha_id", ""),
                captcha_img=data.get("item", ""),
            )

        if code != ResponseCode.OK:
            msg = result.get("msg", f"Unknown error code {code}")
            raise AuthenticationError(f"Login failed: {msg} (code={code})")

        login_data = result.get("data", {})

        # Update server public key — CRITICAL for decrypting all subsequent responses
        server_secret = login_data.get("server_secret_info", {})
        if server_secret.get("public_key"):
            new_server_pub = server_secret["public_key"]
            self._data.server_public_key = new_server_pub
            self._shared_key = self._ecdh.compute_shared_secret(new_server_pub)
            _LOGGER.info("ECDH key exchange complete — server key updated")
        else:
            _LOGGER.warning("Server did not return a new public key — response decryption may fail")
            # Fall back: use the default key for decryption too
            self._shared_key = self._ecdh.compute_shared_secret(SERVER_PUBLIC_KEY_DEFAULT)

        # Store auth data
        self._auth_token = login_data.get("auth_token", "")
        self._token_expires = login_data.get("token_expires_at", 0)
        self._user_id = login_data.get("user_id", "")
        self._data.user_id = self._user_id
        self._data.email = login_data.get("email", self._email)
        self._data.nick_name = login_data.get("nick_name", "")

        _LOGGER.info(
            "Login successful: user=%s token_expires=%s",
            self._data.nick_name or self._email,
            self._token_expires,
        )
        return login_data

    async def send_verify_code(self, message_type: int = 2) -> None:
        """Request a 2FA verification code.

        message_type: 0=SMS, 1=Push, 2=Email
        """
        await self._post(API_SEND_VERIFY_CODE_PATH, {"message_type": message_type})

    async def trust_device(self, verify_code: str) -> None:
        """Trust the current device after 2FA verification."""
        await self._post(API_TRUST_DEVICE_PATH, {"verify_code": verify_code})

    async def get_station_list(self) -> list[StationData]:
        """Fetch all stations/homebases."""
        result = await self._post(API_STATION_LIST_PATH, {
            "device_sn": "",
            "num": 1000,
            "orderby": "",
            "page": 0,
            "station_sn": "",
            "time_zone": 3600000,
        })

        _LOGGER.debug("Station list response code=%s", result.get("code"))
        if result.get("code") != ResponseCode.OK:
            raise EufyCloudApiError(f"Failed to get stations: {result.get('msg')}")

        raw_response_data = result.get("data", [])
        _LOGGER.debug(
            "Station list raw data type=%s len=%s preview=%s",
            type(raw_response_data).__name__,
            len(raw_response_data) if isinstance(raw_response_data, (list, str)) else "?",
            repr(str(raw_response_data)[:200]),
        )

        raw_data = self._decrypt_response(raw_response_data)
        if not isinstance(raw_data, list):
            _LOGGER.warning("Station list decrypt result is not a list: type=%s", type(raw_data).__name__)
            raw_data = []
        else:
            _LOGGER.info("Station list: %d stations found", len(raw_data))

        stations: list[StationData] = []
        for raw in raw_data:
            try:
                device_type_val = raw.get("device_type", 0)
                try:
                    dt = DeviceType(device_type_val)
                except ValueError:
                    dt = DeviceType.STATION

                station = StationData(
                    station_sn=raw.get("station_sn", ""),
                    station_name=raw.get("station_name", ""),
                    device_type=dt,
                    p2p_did=raw.get("p2p_did", ""),
                    member=raw.get("member", {}),
                    main_sw_version=raw.get("main_sw_version", ""),
                    main_hw_version=raw.get("main_hw_version", ""),
                    ip_addr=raw.get("ip_addr", ""),
                    mac_addr=raw.get("mac_addr", ""),
                    app_conn=raw.get("app_conn", ""),
                    raw=raw,
                )

                # Parse guard mode
                guard_mode_val = raw.get("guard_mode", -1)
                try:
                    station.guard_mode = GuardMode(guard_mode_val)
                except ValueError:
                    station.guard_mode = GuardMode.UNKNOWN

                current_mode_val = raw.get("current_mode", -1)
                try:
                    station.current_mode = GuardMode(current_mode_val)
                except ValueError:
                    station.current_mode = GuardMode.UNKNOWN

                # Decode P2P cloud IPs
                if station.app_conn:
                    station.p2p_cloud_ips = decode_p2p_cloud_ips(station.app_conn)

                # Device list under this station
                station.devices = [
                    d.get("device_sn", "")
                    for d in raw.get("devices", [])
                    if d.get("device_sn")
                ]

                self.stations[station.station_sn] = station
                stations.append(station)
            except Exception:
                _LOGGER.exception("Error parsing station data: %s", raw)

        return stations

    async def get_device_list(self) -> list[DeviceData]:
        """Fetch all devices."""
        result = await self._post(API_DEVICE_LIST_PATH, {
            "device_sn": "",
            "num": 1000,
            "orderby": "",
            "page": 0,
            "station_sn": "",
            "time_zone": 3600000,
        })

        _LOGGER.debug("Device list response code=%s", result.get("code"))
        if result.get("code") != ResponseCode.OK:
            raise EufyCloudApiError(f"Failed to get devices: {result.get('msg')}")

        raw_response_data = result.get("data", [])
        _LOGGER.debug(
            "Device list raw data type=%s len=%s preview=%s",
            type(raw_response_data).__name__,
            len(raw_response_data) if isinstance(raw_response_data, (list, str)) else "?",
            repr(str(raw_response_data)[:200]),
        )

        raw_data = self._decrypt_response(raw_response_data)
        if not isinstance(raw_data, list):
            _LOGGER.warning("Device list decrypt result is not a list: type=%s val=%s", type(raw_data).__name__, repr(str(raw_data)[:200]))
            raw_data = []
        else:
            _LOGGER.info("Device list: %d devices found", len(raw_data))
            # Dump ALL keys of the first device so we know the exact field names
            if raw_data:
                first = raw_data[0]
                _LOGGER.info("First device ALL keys: %s", list(first.keys()) if isinstance(first, dict) else type(first).__name__)
                _LOGGER.info("First device data: %s", {k: repr(str(v))[:80] for k, v in first.items()} if isinstance(first, dict) else repr(str(first))[:300])

        devices: list[DeviceData] = []
        for raw in raw_data:
            try:
                device_type_val = raw.get("device_type", 0)
                try:
                    dt = DeviceType(device_type_val)
                except ValueError:
                    # Don't skip unknown types — still create the device
                    _LOGGER.warning(
                        "Unknown device type %d for %s, treating as generic camera",
                        device_type_val, raw.get("device_sn"),
                    )
                    dt = DeviceType.CAMERA

                device = DeviceData(
                    device_sn=raw.get("device_sn", ""),
                    device_name=raw.get("device_name", ""),
                    device_type=dt,
                    station_sn=raw.get("station_sn", ""),
                    device_model=raw.get("device_model", ""),
                    device_channel=raw.get("device_channel", 0),
                    main_sw_version=raw.get("main_sw_version", ""),
                    main_hw_version=raw.get("main_hw_version", ""),
                    ip_addr=raw.get("ip_addr", ""),
                    mac_addr=raw.get("mac_addr", ""),
                    battery_level=raw.get("battery_level", -1),
                    raw=raw,
                )

                # Extract event image URL from cloud data.
                # cover_path is a local SD card path (not a URL) — skip it.
                # Only use fields that are actual HTTP URLs.
                for url_field in ("pic_url", "event_pic_url", "last_pic_url", "cover_path"):
                    val = raw.get(url_field, "")
                    if val and (val.startswith("http://") or val.startswith("https://")):
                        device.last_event_pic_url = val
                        break

                # WiFi RSSI
                wifi = raw.get("wifi_rssi") or raw.get("wifiRssi") or 0
                try:
                    device.wifi_rssi = int(wifi)
                except (ValueError, TypeError):
                    pass

                # Online status
                device.is_online = raw.get("status", 0) == 1 or raw.get("online", False)

                # Parse params
                for param in raw.get("params", []):
                    ptype = param.get("param_type")
                    pval = param.get("param_value")
                    if ptype is not None:
                        device.params[ptype] = pval

                _LOGGER.debug(
                    "Device: %s (%s) type=%d cover=%s online=%s battery=%d",
                    device.device_name, device.device_sn, device_type_val,
                    bool(cover), device.is_online, device.battery_level,
                )

                self.devices[device.device_sn] = device
                devices.append(device)
            except Exception:
                _LOGGER.exception("Error parsing device data: %s", raw)

        return devices

    async def set_device_params(
        self,
        device_sn: str,
        station_sn: str,
        params: list[dict[str, Any]],
    ) -> None:
        """Set device parameters via the cloud API."""
        result = await self._post(API_SET_PARAMS_PATH, {
            "device_sn": device_sn,
            "station_sn": station_sn,
            "params": params,
        })
        if result.get("code") != ResponseCode.OK:
            raise EufyCloudApiError(f"Failed to set params: {result.get('msg')}")

    async def set_guard_mode(self, station_sn: str, mode: GuardMode) -> None:
        """Set the guard mode for a station via REST API (ParamType 1224)."""
        await self.set_device_params(
            device_sn=station_sn,
            station_sn=station_sn,
            params=[{"param_type": 1224, "param_value": str(mode.value)}],
        )
        if station_sn in self.stations:
            self.stations[station_sn].guard_mode = mode

    async def get_dsk_keys(self) -> dict[str, dict[str, Any]]:
        """Get DSK keys for P2P connections."""
        result = await self._post(API_DSK_KEYS_PATH, {})
        if result.get("code") != ResponseCode.OK:
            _LOGGER.warning("Failed to get DSK keys: %s", result.get("msg"))
            return {}

        keys: dict[str, dict[str, Any]] = {}
        for item in result.get("data", []):
            sn = item.get("station_sn", "")
            if sn:
                keys[sn] = item
        return keys

    async def get_ciphers(
        self, cipher_ids: list[int], user_id: str
    ) -> dict[int, str]:
        """Get cipher (RSA private keys) for P2P Level 2 encryption."""
        result = await self._post(API_CIPHER_PATH, {
            "cipher_ids": cipher_ids,
            "user_id": user_id,
        })
        if result.get("code") != ResponseCode.OK:
            return {}

        raw_data = self._decrypt_response(result.get("data", []))
        if not isinstance(raw_data, list):
            return {}

        ciphers: dict[int, str] = {}
        for item in raw_data:
            cid = item.get("cipher_id")
            pk = item.get("private_key", "")
            if cid is not None and pk:
                ciphers[cid] = pk
        return ciphers

    async def get_history(
        self,
        device_sn: str = "",
        station_sn: str = "",
        start_time: int = 0,
        end_time: int | None = None,
        num: int = 100,
    ) -> list[dict[str, Any]]:
        """Get event history records."""
        if end_time is None:
            end_time = int(time.time())
        if start_time == 0:
            start_time = 1230768000  # 2009-01-01

        result = await self._post("v2/event/app/get_all_history_record", {
            "device_sn": device_sn,
            "end_time": end_time,
            "exclude_guest": False,
            "house_id": "HOUSEID_ALL_DEVICE",
            "id": 0,
            "id_type": 1,
            "is_favorite": False,
            "num": num,
            "pullup": True,
            "shared": True,
            "start_time": start_time,
            "station_sn": station_sn,
            "storage": 0,
        })

        _LOGGER.debug("History response code=%s", result.get("code"))
        if result.get("code") != ResponseCode.OK:
            _LOGGER.warning("History fetch failed: code=%s msg=%s", result.get("code"), result.get("msg"))
            return []

        raw_data = self._decrypt_response(result.get("data", []))
        if isinstance(raw_data, list):
            _LOGGER.info("History: %d events found", len(raw_data))
            if raw_data:
                first = raw_data[0]
                _LOGGER.info("First event keys: %s", list(first.keys()) if isinstance(first, dict) else type(first).__name__)
                _LOGGER.info("First event data: %s", {k: repr(str(v))[:80] for k, v in first.items()} if isinstance(first, dict) else repr(str(first))[:300])
        else:
            _LOGGER.warning("History decrypt result is not a list: type=%s", type(raw_data).__name__)
        return raw_data if isinstance(raw_data, list) else []

    async def register_push_token(self, token: str) -> bool:
        """Register an FCM push token with Eufy's cloud."""
        result = await self._post(API_REGISTER_PUSH_TOKEN_PATH, {
            "is_notification_enable": True,
            "token": token,
        })
        return result.get("code") == ResponseCode.OK

    async def check_push_token(self) -> bool:
        """Check if the push token is still valid."""
        result = await self._post(API_CHECK_PUSH_TOKEN_PATH, {})
        return result.get("code") == ResponseCode.OK

    async def fetch_latest_thumbnails(self) -> None:
        """Fetch the latest event history and populate device thumbnails.

        Called on startup to ensure camera entities have a preview image
        even before any push notification arrives.
        """
        try:
            events = await self.get_history(num=50)
            # Events are typically sorted newest first
            seen: set[str] = set()
            for event in events:
                sn = event.get("device_sn", "")
                if not sn or sn in seen:
                    continue
                # Only use actual HTTP URLs, not local SD card paths
                pic = ""
                for field in ("pic_url", "thumb_url", "cover_path", "file_path"):
                    val = event.get(field, "")
                    if val and (val.startswith("http://") or val.startswith("https://")):
                        pic = val
                        break
                if pic and sn in self.devices:
                    device = self.devices[sn]
                    if not device.last_event_pic_url:
                        device.last_event_pic_url = pic
                        device.last_event_time = event.get("event_time", 0)
                        _LOGGER.debug("Thumbnail for %s: %s", sn, pic[:80])
                    seen.add(sn)
        except Exception:
            _LOGGER.debug("Failed to fetch event thumbnails", exc_info=True)

    async def refresh_data(self) -> None:
        """Refresh all stations and devices from the cloud."""
        # Check token expiry
        if self._token_expires and time.time() > self._token_expires - 86400:
            _LOGGER.info("Token expiring soon, re-authenticating")
            await self.login()

        await self.get_station_list()
        await self.get_device_list()
