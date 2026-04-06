"""Binary sensors for Eufy Security devices."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
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
    entities: list[BinarySensorEntity] = []

    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyMotionSensor(coordinator, device))
            entities.append(EufyPersonSensor(coordinator, device))
        if device.is_sensor:
            entities.append(EufyDoorSensor(coordinator, device))
        if device.is_camera or device.is_doorbell:
            entities.append(EufyOnlineSensor(coordinator, device))

    async_add_entities(entities)


class EufyMotionSensor(EufySecurityEntity, BinarySensorEntity):
    """Motion detection binary sensor."""

    _attr_name = "Motion"
    _attr_device_class = BinarySensorDeviceClass.MOTION

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "motion")
        self._auto_off_unsub = None

    @property
    def is_on(self) -> bool | None:
        device = self._device
        return device.motion_detected if device else None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Reset motion after coordinator update if it was a push."""
        super()._handle_coordinator_update()
        data = self.coordinator.data
        if isinstance(data, dict) and "push" in data:
            # Auto-clear motion after 30 seconds
            device = self._device
            if device and device.motion_detected:
                self.hass.loop.call_later(30, self._clear_motion)

    def _clear_motion(self) -> None:
        device = self._device
        if device:
            device.motion_detected = False
            self.async_write_ha_state()


class EufyPersonSensor(EufySecurityEntity, BinarySensorEntity):
    """Person detection binary sensor."""

    _attr_name = "Person"
    _attr_device_class = BinarySensorDeviceClass.OCCUPANCY

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "person")

    @property
    def is_on(self) -> bool | None:
        device = self._device
        return device.person_detected if device else None

    @callback
    def _handle_coordinator_update(self) -> None:
        super()._handle_coordinator_update()
        data = self.coordinator.data
        if isinstance(data, dict) and "push" in data:
            device = self._device
            if device and device.person_detected:
                self.hass.loop.call_later(30, self._clear)

    def _clear(self) -> None:
        device = self._device
        if device:
            device.person_detected = False
            self.async_write_ha_state()


class EufyDoorSensor(EufySecurityEntity, BinarySensorEntity):
    """Door/window contact sensor."""

    _attr_name = "Contact"
    _attr_device_class = BinarySensorDeviceClass.DOOR

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "contact")

    @property
    def is_on(self) -> bool | None:
        device = self._device
        return device.sensor_open if device else None


class EufyOnlineSensor(EufySecurityEntity, BinarySensorEntity):
    """Device online/offline status."""

    _attr_name = "Online"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = "diagnostic"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "online")

    @property
    def is_on(self) -> bool | None:
        device = self._device
        return device.is_online if device else None
