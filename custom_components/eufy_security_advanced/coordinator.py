"""Data update coordinator for Eufy Security Advanced.

Architecture:
- Push notifications (FCM) are the PRIMARY source of real-time state updates
- Cloud polling is a SAFETY NET that runs every 10 minutes to catch anything push missed
- P2P sessions are pooled per station and reused across all commands
- MQTT provides smart lock events
- Session conflicts (Eufy app vs HA) are handled gracefully with auto-reconnect
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_COUNTRY, DOMAIN, UPDATE_INTERVAL_SECONDS
from .lib.cloud_api import (
    AuthenticationError,
    EufyCloudApi,
    EufyCloudApiError,
)
from .lib.models import CloudPersistentData, DeviceData, PushMessage, StationData
from .lib.mqtt.client import EufyMQTTClient
from .lib.push.fcm import FCMRegistration
from .lib.push.mcs import MCSClient
from .lib.push.parser import parse_push_message
from .lib.types import (
    CusPushEvent,
    DoorbellPushEvent,
    GuardMode,
    IndoorPushEvent,
    LockPushEvent,
)

_LOGGER = logging.getLogger(__name__)


class EufySecurityCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Central coordinator — push-first updates, pooled P2P, graceful conflict recovery."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=UPDATE_INTERVAL_SECONDS),
        )
        self.entry = entry
        self._api: EufyCloudApi | None = None
        self._push_fcm: FCMRegistration | None = None
        self._push_mcs: MCSClient | None = None
        self._push_task: asyncio.Task | None = None
        self._mqtt: EufyMQTTClient | None = None

        # Push status tracking
        self._push_connected = False
        self._last_push_time: float = 0
        self._session_conflict_count = 0

        # Managers (initialized in async_setup)
        self.stream_manager = None
        self.p2p_pool = None

        # Device/station caches
        self.stations: dict[str, StationData] = {}
        self.devices: dict[str, DeviceData] = {}

    @property
    def api(self) -> EufyCloudApi:
        assert self._api is not None
        return self._api

    @property
    def push_connected(self) -> bool:
        return self._push_connected

    async def async_setup(self) -> None:
        """Initialize cloud API, P2P pool, push, MQTT, and stream manager."""
        data = self.entry.data
        session = async_get_clientsession(self.hass)

        persistent = CloudPersistentData(
            user_id=data.get("user_id", ""),
            email=data.get(CONF_EMAIL, ""),
            client_private_key=data.get("client_private_key", ""),
            server_public_key=data.get("server_public_key", ""),
            auth_token=data.get("auth_token", ""),
            token_expires_at=data.get("token_expires_at", 0),
            api_base=data.get("api_base", ""),
        )

        self._api = EufyCloudApi(
            email=data[CONF_EMAIL],
            password=data[CONF_PASSWORD],
            country=data.get(CONF_COUNTRY, "US"),
            session=session,
            persistent_data=persistent,
        )

        # Only login if we don't have a valid token
        if not persistent.auth_token:
            await self._login_with_retry()
        else:
            _LOGGER.debug("Using saved auth token, skipping login")

        # Fetch initial data
        await self._api.get_station_list()
        await self._api.get_device_list()
        self.stations = self._api.stations
        self.devices = self._api.devices

        _LOGGER.info(
            "Loaded %d stations, %d devices",
            len(self.stations), len(self.devices),
        )
        for sn, dev in self.devices.items():
            _LOGGER.info(
                "  Device: %s (%s) type=%s camera=%s doorbell=%s",
                dev.device_name, sn, dev.device_type.name,
                dev.is_camera, dev.is_doorbell,
            )

        # Fetch latest event thumbnails so camera entities have a preview image
        await self._api.fetch_latest_thumbnails()

        # Initialize P2P session pool
        from .p2p_manager import P2PSessionPool
        self.p2p_pool = P2PSessionPool(self)

        # Initialize preemptive stream manager
        from .stream_manager import PreemptiveStreamManager
        self.stream_manager = PreemptiveStreamManager(self)

        # Start push notifications
        await self._setup_push()

        # Start MQTT for smart locks
        lock_sns = [d.device_sn for d in self.devices.values() if d.is_lock]
        if lock_sns:
            await self._setup_mqtt(lock_sns)

    async def _login_with_retry(self) -> None:
        """Login with retry on session conflict (another session kicked us)."""
        for attempt in range(3):
            try:
                await self._api.login()
                self._session_conflict_count = 0
                return
            except AuthenticationError as err:
                if "401" in str(err) and attempt < 2:
                    self._session_conflict_count += 1
                    _LOGGER.warning(
                        "Session conflict detected (attempt %d/3) — "
                        "another app may be using this Eufy account. "
                        "Retrying in 5s. Consider using a secondary account.",
                        attempt + 1,
                    )
                    await asyncio.sleep(5)
                    continue
                raise

    async def _setup_push(self) -> None:
        """Register with FCM and start MCS listener."""
        try:
            session = async_get_clientsession(self.hass)
            self._push_fcm = FCMRegistration(session=session)
            gcm_token = await self._push_fcm.register()

            await self._api.register_push_token(gcm_token)

            self._push_mcs = MCSClient(
                android_id=self._push_fcm.android_id,
                security_token=self._push_fcm.security_token,
                on_message=self._on_push_message,
                on_disconnect=self._on_push_disconnect,
            )
            self._push_task = asyncio.create_task(self._push_mcs.run_forever())
            self._push_connected = True
            _LOGGER.info("Push notifications enabled")

        except Exception:
            self._push_connected = False
            _LOGGER.warning(
                "Push notifications failed — falling back to polling only",
                exc_info=True,
            )

    def _on_push_disconnect(self) -> None:
        """Handle push connection loss."""
        self._push_connected = False
        _LOGGER.warning("Push connection lost — MCS will auto-reconnect")

    async def _setup_mqtt(self, lock_sns: list[str]) -> None:
        """Set up MQTT for smart lock events."""
        try:
            self._mqtt = EufyMQTTClient(
                user_id=self._api.persistent_data.user_id,
                email=self.entry.data[CONF_EMAIL],
                api_base=self._api.persistent_data.api_base,
                device_sns=lock_sns,
                on_lock_event=self._on_lock_event,
            )
            await self._mqtt.connect()
            _LOGGER.info("MQTT enabled for %d locks", len(lock_sns))
        except Exception:
            _LOGGER.warning("MQTT for locks failed", exc_info=True)

    # ----- Push message handling (PRIMARY update source) -----

    @callback
    def _on_push_message(self, raw: dict[str, Any]) -> None:
        """Handle a raw FCM push message — primary real-time update source."""
        self._push_connected = True
        self._last_push_time = time.monotonic()

        msg = parse_push_message(raw)
        if not msg:
            return

        _LOGGER.debug(
            "Push: device=%s event=%d title=%s",
            msg.device_sn, msg.event_type, msg.title,
        )

        # Update device state from push (immediate, no polling delay)
        device = self.devices.get(msg.device_sn)
        if device:
            self._apply_push_to_device(device, msg)

        # Update station state
        station = self.stations.get(msg.station_sn)
        if station and msg.guard_mode is not None:
            try:
                station.guard_mode = GuardMode(msg.guard_mode)
                station.current_mode = GuardMode(msg.guard_mode)
            except ValueError:
                pass

        # Preemptive stream
        if self.stream_manager:
            self.stream_manager.handle_push_event(msg)

        # Fire HA event for automations (Stage 3 will expand this)
        self.hass.bus.async_fire(f"{DOMAIN}_event", {
            "device_sn": msg.device_sn,
            "station_sn": msg.station_sn,
            "event_type": msg.event_type,
            "title": msg.title,
            "content": msg.content,
            "pic_url": msg.pic_url,
            "person_name": msg.person_name,
        })

        # Notify HA entities of update
        self.async_set_updated_data({"push": msg})

    def _apply_push_to_device(self, device: DeviceData, msg: PushMessage) -> None:
        """Update device state from push notification."""
        if msg.pic_url:
            device.last_event_pic_url = msg.pic_url
        if msg.event_time:
            device.last_event_time = msg.event_time

        et = msg.event_type

        if et in (DoorbellPushEvent.MOTION_DETECTION, IndoorPushEvent.MOTION, 3101):
            device.motion_detected = True
        elif et in (
            DoorbellPushEvent.FACE_DETECTION, IndoorPushEvent.FACE,
            DoorbellPushEvent.FAMILY_DETECTION, 3102, 3303,
        ):
            device.person_detected = True
        elif et in (DoorbellPushEvent.PET_DETECTION, IndoorPushEvent.PET, 3106):
            device.pet_detected = True
        elif et in (DoorbellPushEvent.VEHICLE_DETECTION, 3107):
            device.vehicle_detected = True
        elif et == IndoorPushEvent.CRYING:
            device.crying_detected = True
        elif et in (IndoorPushEvent.SOUND, 3108):
            device.sound_detected = True

        if msg.sensor_open is not None:
            device.sensor_open = msg.sensor_open

        if et == CusPushEvent.CAM_STATE:
            device.is_online = msg.raw.get("m", 1) == 1

        if device.is_lock:
            self._apply_lock_push(device, msg)

    def _apply_lock_push(self, device: DeviceData, msg: PushMessage) -> None:
        et = msg.event_type
        device.lock_event_type = et
        device.lock_event_user = msg.nick_name or msg.user_id

        if et in (LockPushEvent.MANUAL_LOCK, LockPushEvent.KEYPAD_LOCK,
                  LockPushEvent.APP_LOCK, LockPushEvent.AUTO_LOCK):
            device.is_locked = True
        elif et in (LockPushEvent.MANUAL_UNLOCK, LockPushEvent.AUTO_UNLOCK,
                    LockPushEvent.PW_UNLOCK, LockPushEvent.FINGERPRINT_UNLOCK,
                    LockPushEvent.APP_UNLOCK):
            device.is_locked = False

    @callback
    def _on_lock_event(self, data: dict[str, Any]) -> None:
        """Handle MQTT smart lock event."""
        device_sn = data.get("device_sn", "")
        device = self.devices.get(device_sn)
        if not device:
            return

        device.lock_event_type = data.get("data_event_type", 0)
        device.lock_event_user = data.get("nick_name", "")

        lock_state = data.get("lock_state", "")
        if lock_state == "1":
            device.is_locked = True
        elif lock_state == "0":
            device.is_locked = False

        self.hass.bus.async_fire(f"{DOMAIN}_event", {
            "device_sn": device_sn,
            "event_type": device.lock_event_type,
            "lock_state": lock_state,
            "user": device.lock_event_user,
        })

        self.async_set_updated_data({"mqtt_lock": data})

    # ----- Cloud polling (SAFETY NET — catches what push missed) -----

    async def _async_update_data(self) -> dict[str, Any]:
        """Periodic cloud poll — safety net for state that push didn't cover."""
        try:
            await self._api.refresh_data()

            # Merge cloud data without overwriting push-driven state.
            # Only update fields the cloud provides that push doesn't.
            for sn, cloud_station in self._api.stations.items():
                existing = self.stations.get(sn)
                if existing:
                    existing.ip_addr = cloud_station.ip_addr
                    existing.main_sw_version = cloud_station.main_sw_version
                    existing.raw = cloud_station.raw
                    # Only update guard mode from cloud if push hasn't sent one recently
                    if time.monotonic() - self._last_push_time > 60:
                        existing.guard_mode = cloud_station.guard_mode
                        existing.current_mode = cloud_station.current_mode
                else:
                    self.stations[sn] = cloud_station

            for sn, cloud_device in self._api.devices.items():
                existing = self.devices.get(sn)
                if existing:
                    existing.ip_addr = cloud_device.ip_addr
                    existing.main_sw_version = cloud_device.main_sw_version
                    existing.main_hw_version = cloud_device.main_hw_version
                    existing.raw = cloud_device.raw
                    # Update battery from cloud (push doesn't send periodic battery)
                    if cloud_device.battery_level >= 0:
                        existing.battery_level = cloud_device.battery_level
                    # Update params from cloud
                    for k, v in cloud_device.params.items():
                        existing.params.setdefault(k, v)
                else:
                    self.devices[sn] = cloud_device

            return {"stations": self.stations, "devices": self.devices}

        except AuthenticationError:
            _LOGGER.warning("Session expired during poll, re-authenticating")
            try:
                await self._login_with_retry()
                return {"stations": self.stations, "devices": self.devices}
            except Exception as err:
                raise UpdateFailed(f"Re-auth failed: {err}") from err

        except EufyCloudApiError as err:
            raise UpdateFailed(f"Cloud API error: {err}") from err

    # ----- Shutdown -----

    async def async_shutdown(self) -> None:
        """Clean up all resources."""
        if self.stream_manager:
            await self.stream_manager.stop_all()
        if self.p2p_pool:
            await self.p2p_pool.shutdown()
        if self._push_task and not self._push_task.done():
            self._push_task.cancel()
        if self._push_mcs:
            await self._push_mcs.disconnect()
        if self._mqtt:
            await self._mqtt.disconnect()
        if self._api:
            await self._api.close()
