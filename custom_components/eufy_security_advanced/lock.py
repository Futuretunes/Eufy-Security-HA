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

_LOGGER = logging.getLogger(__name__)


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
    """Smart lock entity."""

    _attr_name = "Lock"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "lock")

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

    async def async_lock(self, **kwargs) -> None:
        """Lock the device via P2P command."""
        _LOGGER.info("Lock command for %s — P2P lock control pending implementation", self._device_sn)
        # TODO: Implement P2P lock command
        # This requires establishing a P2P session to the station and sending
        # the appropriate CMD_SET_PAYLOAD with lock command
        device = self._device
        if device:
            device.is_locked = True
            self.async_write_ha_state()

    async def async_unlock(self, **kwargs) -> None:
        """Unlock the device via P2P command."""
        _LOGGER.info("Unlock command for %s — P2P lock control pending implementation", self._device_sn)
        # TODO: Implement P2P unlock command
        device = self._device
        if device:
            device.is_locked = False
            self.async_write_ha_state()
