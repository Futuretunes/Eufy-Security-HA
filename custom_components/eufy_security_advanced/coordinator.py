"""Data update coordinator for Eufy Security Advanced."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_PASSWORD
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_COUNTRY, DOMAIN, UPDATE_INTERVAL_SECONDS
from .lib.cloud_api import EufyCloudApi, EufyCloudApiError
from .lib.models import CloudPersistentData, DeviceData, PushMessage, StationData
from .lib.mqtt.client import EufyMQTTClient
from .lib.push.fcm import FCMRegistration
from .lib.push.mcs import MCSClient
from .lib.push.parser import parse_push_message
from .lib.types import (
    DOORBELL_TYPES,
    LOCK_TYPES,
    CusPushEvent,
    DoorbellPushEvent,
    GuardMode,
    IndoorPushEvent,
    LockPushEvent,
)

_LOGGER = logging.getLogger(__name__)


class EufySecurityCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    """Coordinator that manages cloud polling, push notifications, and MQTT."""

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

        # Device/station caches
        self.stations: dict[str, StationData] = {}
        self.devices: dict[str, DeviceData] = {}

    @property
    def api(self) -> EufyCloudApi:
        assert self._api is not None
        return self._api

    async def async_setup(self) -> None:
        """Initialize the cloud API, authenticate, and discover devices."""
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

        # Login if no valid token
        if not persistent.auth_token:
            await self._api.login()

        # Fetch initial data
        await self._api.get_station_list()
        await self._api.get_device_list()
        self.stations = self._api.stations
        self.devices = self._api.devices

        # Start push notifications
        await self._setup_push()

        # Start MQTT for smart locks
        lock_sns = [
            d.device_sn for d in self.devices.values() if d.is_lock
        ]
        if lock_sns:
            await self._setup_mqtt(lock_sns)

    async def _setup_push(self) -> None:
        """Register with FCM and start MCS listener."""
        try:
            session = async_get_clientsession(self.hass)
            self._push_fcm = FCMRegistration(session=session)
            gcm_token = await self._push_fcm.register()

            # Register token with Eufy
            await self._api.register_push_token(gcm_token)

            # Start MCS persistent connection
            self._push_mcs = MCSClient(
                android_id=self._push_fcm.android_id,
                security_token=self._push_fcm.security_token,
                on_message=self._on_push_message,
            )
            self._push_task = asyncio.create_task(self._push_mcs.run_forever())
            _LOGGER.info("Push notifications enabled")

        except Exception:
            _LOGGER.warning("Failed to set up push notifications, falling back to polling only", exc_info=True)

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
            _LOGGER.info("MQTT lock notifications enabled for %d locks", len(lock_sns))
        except Exception:
            _LOGGER.warning("Failed to set up MQTT for locks", exc_info=True)

    @callback
    def _on_push_message(self, raw: dict[str, Any]) -> None:
        """Handle a raw FCM push message."""
        msg = parse_push_message(raw)
        if not msg:
            return

        _LOGGER.debug(
            "Push: device=%s event=%d title=%s",
            msg.device_sn, msg.event_type, msg.title,
        )

        # Update device state
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

        # Notify HA of update
        self.async_set_updated_data({"push": msg})

    def _apply_push_to_device(self, device: DeviceData, msg: PushMessage) -> None:
        """Update device state from a push notification."""
        if msg.pic_url:
            device.last_event_pic_url = msg.pic_url
        if msg.event_time:
            device.last_event_time = msg.event_time

        et = msg.event_type

        # Motion / person / pet / vehicle detection
        if et in (
            DoorbellPushEvent.MOTION_DETECTION,
            IndoorPushEvent.MOTION,
            3101,
        ):
            device.motion_detected = True
        elif et in (
            DoorbellPushEvent.FACE_DETECTION,
            IndoorPushEvent.FACE,
            DoorbellPushEvent.FAMILY_DETECTION,
            3102, 3303,
        ):
            device.person_detected = True
            if msg.person_name:
                device.person_detected = True
        elif et in (DoorbellPushEvent.PET_DETECTION, IndoorPushEvent.PET, 3106):
            device.pet_detected = True
        elif et in (DoorbellPushEvent.VEHICLE_DETECTION, 3107):
            device.vehicle_detected = True
        elif et == IndoorPushEvent.CRYING:
            device.crying_detected = True
        elif et in (IndoorPushEvent.SOUND, 3108):
            device.sound_detected = True

        # Sensor
        if msg.sensor_open is not None:
            device.sensor_open = msg.sensor_open

        # Camera state
        if et == CusPushEvent.CAM_STATE:
            status = msg.raw.get("m", 1)
            device.is_online = status == 1

        # Lock events
        if device.is_lock:
            self._apply_lock_push(device, msg)

    def _apply_lock_push(self, device: DeviceData, msg: PushMessage) -> None:
        """Update lock state from push notification."""
        et = msg.event_type
        device.lock_event_type = et
        device.lock_event_user = msg.nick_name or msg.user_id

        if et in (
            LockPushEvent.MANUAL_LOCK,
            LockPushEvent.KEYPAD_LOCK,
            LockPushEvent.APP_LOCK,
            LockPushEvent.AUTO_LOCK,
        ):
            device.is_locked = True
        elif et in (
            LockPushEvent.MANUAL_UNLOCK,
            LockPushEvent.AUTO_UNLOCK,
            LockPushEvent.PW_UNLOCK,
            LockPushEvent.FINGERPRINT_UNLOCK,
            LockPushEvent.APP_UNLOCK,
        ):
            device.is_locked = False

    @callback
    def _on_lock_event(self, data: dict[str, Any]) -> None:
        """Handle an MQTT smart lock event."""
        device_sn = data.get("device_sn", "")
        device = self.devices.get(device_sn)
        if not device:
            return

        event_type = data.get("data_event_type", 0)
        device.lock_event_type = event_type
        device.lock_event_user = data.get("nick_name", "")

        lock_state = data.get("lock_state", "")
        if lock_state == "1":
            device.is_locked = True
        elif lock_state == "0":
            device.is_locked = False

        _LOGGER.debug("MQTT lock event: %s type=%d", device_sn, event_type)
        self.async_set_updated_data({"mqtt_lock": data})

    async def _async_update_data(self) -> dict[str, Any]:
        """Periodic cloud poll for device/station state."""
        try:
            await self._api.refresh_data()
            self.stations = self._api.stations
            self.devices = self._api.devices
            return {"stations": self.stations, "devices": self.devices}
        except EufyCloudApiError as err:
            raise UpdateFailed(f"Cloud API error: {err}") from err

    async def async_shutdown(self) -> None:
        """Clean up resources."""
        if self._push_task and not self._push_task.done():
            self._push_task.cancel()
        if self._push_mcs:
            await self._push_mcs.disconnect()
        if self._mqtt:
            await self._mqtt.disconnect()
        if self._api:
            await self._api.close()
