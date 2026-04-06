"""Lock platform for Eufy Security smart locks."""

from __future__ import annotations

import logging

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
from .lib.models import DeviceData
from .lib.types import (
    DeviceType,
    LOCK_TYPES,
)

_LOGGER = logging.getLogger(__name__)

# Lock types that use BLE passthrough commands
_BLE_LOCK_TYPES = {
    DeviceType.LOCK_BLE, DeviceType.LOCK_BLE_NO_FINGER,
}

# Lock types that use the smart lock (CMD_TRANSFER_PAYLOAD) protocol
_SMART_LOCK_TYPES = {
    DeviceType.LOCK_8502, DeviceType.LOCK_8506,
    DeviceType.LOCK_85L0, DeviceType.LOCK_85D0, DeviceType.LOCK_85V0,
}

# Lock types that use the simple WiFi video lock protocol (plaintext)
_WIFI_VIDEO_LOCK_TYPES = {
    DeviceType.LOCK_8530, DeviceType.LOCK_8531,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        EufyLock(coordinator, device)
        for device in coordinator.devices.values()
        if device.is_lock
    ]
    async_add_entities(entities)


class EufyLock(EufySecurityEntity, LockEntity):
    """Smart lock entity with P2P lock/unlock support."""

    _attr_name = "Lock"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "lock")
        self._lock_sequence = 0

    @property
    def is_locked(self) -> bool | None:
        device = self._device
        return device.is_locked if device else None

    @property
    def extra_state_attributes(self) -> dict:
        device = self._device
        if not device:
            return {}
        attrs = {}
        if device.lock_event_type:
            attrs["last_event_type"] = device.lock_event_type
        if device.lock_event_user:
            attrs["last_event_user"] = device.lock_event_user
        return attrs

    async def _get_p2p_session(self):
        """Get or create a P2P session to the lock's station."""
        device = self._device
        if not device:
            return None

        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            _LOGGER.error("Station %s not found for lock %s", device.station_sn, device.device_sn)
            return None

        from .lib.p2p.session import P2PSession

        dsk_keys = await self.coordinator.api.get_dsk_keys()
        dsk_data = dsk_keys.get(station.station_sn, {})
        dsk_key = dsk_data.get("dsk_key", "")

        session = P2PSession(
            station_sn=station.station_sn,
            p2p_did=station.p2p_did,
            dsk_key=dsk_key,
            cloud_ips=station.p2p_cloud_ips or [],
            admin_user_id=self.coordinator.api.persistent_data.user_id,
            get_cipher_callback=self.coordinator.api.get_ciphers,
        )

        connected = await session.connect()
        if not connected:
            _LOGGER.error("Failed to connect P2P for lock %s", device.device_sn)
            return None
        return session

    async def _send_lock_command(self, lock: bool) -> None:
        """Send lock/unlock command via P2P based on lock type."""
        device = self._device
        if not device:
            return

        session = await self._get_p2p_session()
        if not session:
            return

        nick_name = self.coordinator.api.persistent_data.nick_name or ""
        self._lock_sequence += 1

        try:
            if device.device_type in _BLE_LOCK_TYPES:
                await session.lock_device_ble(
                    device_channel=device.device_channel,
                    lock=lock,
                    nick_name=nick_name,
                    lock_sequence=self._lock_sequence,
                )
            elif device.device_type in _SMART_LOCK_TYPES:
                await session.lock_device_smart(
                    device_channel=device.device_channel,
                    lock=lock,
                    nick_name=nick_name,
                    lock_sequence=self._lock_sequence,
                )
            else:
                # Default: WiFi video lock / generic (plaintext payload)
                await session.lock_device(
                    device_channel=device.device_channel,
                    lock=lock,
                    nick_name=nick_name,
                )

            device.is_locked = lock
            self.async_write_ha_state()
            _LOGGER.info("Lock %s: %s", device.device_sn, "locked" if lock else "unlocked")
        except Exception:
            _LOGGER.exception("Failed to %s lock %s", "lock" if lock else "unlock", device.device_sn)
        finally:
            await session.disconnect()

    async def async_lock(self, **kwargs) -> None:
        await self._send_lock_command(lock=True)

    async def async_unlock(self, **kwargs) -> None:
        await self._send_lock_command(lock=False)
