"""Firebase Cloud Messaging registration — FID, Google checkin, GCM token.

This module handles the multi-step FCM registration flow that the Eufy app
uses to receive push notifications. It impersonates the Eufy Android app
to register with Google's FCM infrastructure.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import struct
from typing import Any

import aiohttp

from ...const import (
    FCM_APP_CERT_SHA1,
    FCM_APP_ID,
    FCM_APP_PACKAGE,
    FCM_GOOGLE_API_KEY,
    FCM_PROJECT_ID,
    FCM_SENDER_ID,
)

_LOGGER = logging.getLogger(__name__)

# Checkin protobuf is complex; we use a minimal hand-built version
# instead of depending on compiled proto files.
_CHECKIN_URL = "https://android.clients.google.com/checkin"
_REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
_FID_URL = f"https://firebaseinstallations.googleapis.com/v1/projects/{FCM_PROJECT_ID}/installations"


def _generate_fid() -> str:
    """Generate a Firebase Installation ID (FID).

    Algorithm:
    1. Generate 17 random bytes
    2. Set first byte's upper nibble to 0x70
    3. URL-safe base64, take first 22 chars
    4. Must match /^[cdef][\\w-]{21}$/
    """
    raw = bytearray(os.urandom(17))
    raw[0] = 0x70 | (raw[0] & 0x0F)
    encoded = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")[:22]
    if not re.match(r"^[cdef][\w-]{21}$", encoded):
        # Retry once
        raw = bytearray(os.urandom(17))
        raw[0] = 0x70 | (raw[0] & 0x0F)
        encoded = base64.urlsafe_b64encode(bytes(raw)).decode("ascii")[:22]
    return encoded


def _build_checkin_proto(android_id: int = 0, security_token: int = 0) -> bytes:
    """Build a minimal protobuf CheckinRequest.

    This is a hand-crafted protobuf to avoid requiring compiled proto files.
    Field numbers MUST match the checkin.proto schema exactly:
      https://github.com/nickoala/nicko-push / bropat/eufy-security-client

    Proto field numbering (CheckinRequest):
      1=imei, 2=androidId, 4=checkin, 6=locale, 7=loggingId,
      9=macAddress, 10=meid, 11=accountCookie, 12=timeZone,
      13=securityToken(fixed64), 14=version, 15=otaCert, 17=esn,
      19=macAddressType, 20=fragment, 22=userSerialNumber

    Build sub-message (field 1 of Checkin):
      1=fingerprint, 2=hardware, 3=brand, 4=radio, 6=clientId
    """
    # Protobuf field encoding helpers
    def _varint(value: int) -> bytes:
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    def _field_varint(field_num: int, value: int) -> bytes:
        tag = (field_num << 3) | 0  # wire type 0 = varint
        return _varint(tag) + _varint(value)

    def _field_fixed64(field_num: int, value: int) -> bytes:
        tag = (field_num << 3) | 1  # wire type 1 = 64-bit
        return _varint(tag) + struct.pack("<Q", value)

    def _field_string(field_num: int, value: str | bytes) -> bytes:
        if isinstance(value, str):
            value = value.encode()
        tag = (field_num << 3) | 2  # wire type 2 = length-delimited
        return _varint(tag) + _varint(len(value)) + value

    def _field_submessage(field_num: int, data: bytes) -> bytes:
        tag = (field_num << 3) | 2
        return _varint(tag) + _varint(len(data)) + data

    # Build sub-message: fingerprint(1), hardware(2), brand(3), radio(4), clientId(6)
    build_msg = (
        _field_string(1, "google/razor/flo:5.0.1/LRX22C/1602158:user/release-keys")
        + _field_string(2, "flo")
        + _field_string(3, "google")
        + _field_string(4, "FLO-04.04")
        + _field_string(6, "android-google")  # clientId is field 6, NOT 5
    )

    # Checkin sub-message (field 4 of CheckinRequest)
    checkin_msg = (
        _field_submessage(1, build_msg)  # build
        + _field_varint(2, 0)  # lastCheckinMs (field 2 of Checkin, NOT 3)
    )

    # Main CheckinRequest — field numbers must match proto exactly
    request = (
        _field_string(1, "109269993813709")          # imei (field 1)
        + _field_varint(2, android_id)                # androidId (field 2)
        + _field_submessage(4, checkin_msg)            # checkin (field 4)
        + _field_string(6, "en")                       # locale (field 6)
        + _field_varint(7, 1234567890)                 # loggingId (field 7, NOT 8)
        + _field_string(9, "A1B2C3D4E5F6")            # macAddress (field 9)
        + _field_string(10, "109269993813709")         # meid (field 10)
        + _field_string(12, "GMT")                     # timeZone (field 12, NOT 14)
        + _field_varint(14, 3)                         # version (field 14, NOT 16)
        + _field_string(15, "71Q6Rn2DDZl1zPDVaaeEHItd+Yg=")  # otaCert (field 15) — base64 STRING, not decoded bytes
        + _field_string(17, "ABCDEF01")                # esn (field 17, NOT 19)
        + _field_string(19, "wifi")                    # macAddressType (field 19, NOT 21)
        + _field_varint(20, 0)                         # fragment (field 20, NOT 22)
        + _field_varint(22, 0)                         # userSerialNumber (field 22, NOT 24)
    )

    # securityToken: only include on subsequent checkins (it's fixed64, field 13)
    if security_token:
        request += _field_fixed64(13, security_token)

    return request


def _parse_checkin_response(data: bytes) -> tuple[int, int]:
    """Parse a protobuf CheckinResponse to extract androidId and securityToken.

    From checkin.proto CheckinResponse:
    - Field 7 (fixed64): androidId
    - Field 8 (fixed64): securityToken

    Both are fixed64 (wire type 1 = 8 bytes little-endian), NOT varint.
    """
    pos = 0
    android_id = 0
    security_token = 0

    def read_varint(d: bytes, p: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while p < len(d):
            b = d[p]
            result |= (b & 0x7F) << shift
            p += 1
            if not (b & 0x80):
                break
            shift += 7
        return result, p

    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x07

        if wire_type == 0:  # varint
            _value, pos = read_varint(data, pos)
        elif wire_type == 1:  # 64-bit (fixed64)
            if pos + 8 > len(data):
                break
            value = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            if field_num == 7:
                android_id = value
            elif field_num == 8:
                security_token = value
        elif wire_type == 2:  # length-delimited
            length, pos = read_varint(data, pos)
            pos += length
        elif wire_type == 5:  # 32-bit
            pos += 4
        else:
            break

    return android_id, security_token


class FCMRegistration:
    """Handles the full FCM registration flow."""

    def __init__(self, session: aiohttp.ClientSession | None = None) -> None:
        self._session = session
        self._owns_session = session is None

        # Registration results
        self.fid: str = ""
        self.fid_refresh_token: str = ""
        self.fid_auth_token: str = ""
        self.android_id: int = 0
        self.security_token: int = 0
        self.gcm_token: str = ""

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        return self._session

    async def close(self) -> None:
        if self._owns_session and self._session and not self._session.closed:
            await self._session.close()

    async def register(self) -> str:
        """Run the full registration flow. Returns the GCM token."""
        await self._register_fid()
        await self._google_checkin()
        await self._register_gcm()
        return self.gcm_token

    async def _register_fid(self) -> None:
        """Phase 1: Register a Firebase Installation ID."""
        self.fid = _generate_fid()
        session = await self._ensure_session()

        headers = {
            "X-Android-Package": FCM_APP_PACKAGE,
            "X-Android-Cert": FCM_APP_CERT_SHA1,
            "x-goog-api-key": FCM_GOOGLE_API_KEY,
        }
        body = {
            "fid": self.fid,
            "appId": FCM_APP_ID,
            "authVersion": "FIS_v2",
            "sdkVersion": "a:16.3.1",
        }

        async with session.post(_FID_URL, headers=headers, json=body) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"FID registration failed ({resp.status}): {text}")
            result = await resp.json()

        self.fid = result.get("fid", self.fid)
        self.fid_refresh_token = result.get("refreshToken", "")
        auth_token = result.get("authToken", {})
        self.fid_auth_token = auth_token.get("token", "")

        _LOGGER.debug("FID registered: %s", self.fid)

    async def _google_checkin(self) -> None:
        """Phase 2: Google checkin to get androidId and securityToken."""
        session = await self._ensure_session()

        proto_body = _build_checkin_proto()
        headers = {"Content-Type": "application/x-protobuf"}

        async with session.post(_CHECKIN_URL, headers=headers, data=proto_body) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise RuntimeError(f"Google checkin failed ({resp.status}): {text}")
            response_data = await resp.read()

        self.android_id, self.security_token = _parse_checkin_response(response_data)

        if not self.android_id:
            raise RuntimeError("Checkin response missing androidId")

        _LOGGER.debug("Google checkin: androidId=%d", self.android_id)

    async def _register_gcm(self) -> None:
        """Phase 3: Register for GCM to get the push token."""
        session = await self._ensure_session()

        headers = {
            "Authorization": f"AidLogin {self.android_id}:{self.security_token}",
            "app": FCM_APP_PACKAGE,
            "gcm_ver": "201216023",
            "User-Agent": "Android-GCM/1.5",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        form_data = {
            "X-subtype": FCM_SENDER_ID,
            "sender": FCM_SENDER_ID,
            "X-app_ver": "741",
            "X-osv": "25",
            "X-cliv": "fiid-20.2.0",
            "X-gmsv": "201216023",
            "X-appid": self.fid,
            "X-scope": "*",
            "X-Goog-Firebase-Installations-Auth": self.fid_auth_token,
            "X-gmp_app_id": FCM_APP_ID,
            "X-Firebase-Client": (
                "fire-abt/17.1.1+fire-installations/16.3.1+fire-android/"
                "+fire-analytics/17.4.2+fire-iid/20.2.0+fire-rc/17.0.0"
                "+fire-fcm/20.2.0+fire-cls/17.0.0+fire-cls-ndk/17.0.0"
                "+fire-core/19.3.0"
            ),
            "X-firebase-app-name-hash": "R1dAH9Ui7M-ynoznwBdw01tLxhI",
            "X-Firebase-Client-Log-Type": "1",
            "X-app_ver_name": "v2.2.2_741",
            "app": FCM_APP_PACKAGE,
            "device": str(self.android_id),
            "app_ver": "741",
            "info": "g3EMJXXElLwaQEb1aBJ6XhxiHjPTUxc",
            "gcm_ver": "201216023",
            "plat": "0",
            "cert": FCM_APP_CERT_SHA1,
            "target_ver": "28",
        }

        for attempt in range(5):
            async with session.post(_REGISTER_URL, headers=headers, data=form_data) as resp:
                text = await resp.text()

            if text.startswith("token="):
                self.gcm_token = text.split("=", 1)[1].strip()
                _LOGGER.debug("GCM token registered")
                return

            if text.startswith("Error="):
                _LOGGER.warning("GCM registration error (attempt %d): %s", attempt + 1, text)
                import asyncio
                await asyncio.sleep(10 * (attempt + 1))
                continue

            raise RuntimeError(f"Unexpected GCM response: {text}")

        raise RuntimeError("GCM registration failed after 5 attempts")
