"""Binary sensors for Eufy Security devices and stations."""

from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity, EufyStationEntity
from .lib.models import DeviceData, StationData

_LOGGER = logging.getLogger(__name__)

# Auto-clear delay for detection events (seconds)
_DETECTION_CLEAR_DELAY = 30


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[BinarySensorEntity] = []

    for device in coordinator.devices.values():
        # All devices get a connectivity sensor
        entities.append(EufyConnectedSensor(coordinator, device))

        if device.is_camera or device.is_doorbell:
            entities.append(EufyMotionSensor(coordinator, device))
            entities.append(EufyPersonSensor(coordinator, device))
            entities.append(EufyPetSensor(coordinator, device))
            entities.append(EufyVehicleSensor(coordinator, device))
            entities.append(EufySoundSensor(coordinator, device))
            entities.append(EufyCryingSensor(coordinator, device))

        if device.is_doorbell:
            entities.append(EufyRingingSensor(coordinator, device))

        if device.is_sensor:
            entities.append(EufyDoorSensor(coordinator, device))

        if device.has_battery:
            entities.append(EufyBatteryLowSensor(coordinator, device))

    # Station connectivity
    for station in coordinator.stations.values():
        entities.append(EufyStationConnectedSensor(coordinator, station))

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Helper mixin for auto-clearing detection binary sensors
# ---------------------------------------------------------------------------
class _AutoClearMixin:
    """Mixin that auto-clears a detection flag after a delay."""

    _clear_attr: str = ""

    @callback
    def _handle_coordinator_update(self) -> None:
        super()._handle_coordinator_update()
        device = self._device
        if device and getattr(device, self._clear_attr, False):
            self.hass.loop.call_later(_DETECTION_CLEAR_DELAY, self._clear)

    def _clear(self) -> None:
        device = self._device
        if device:
            setattr(device, self._clear_attr, False)
            self.async_write_ha_state()


# ---------------------------------------------------------------------------
# Device binary sensors
# ---------------------------------------------------------------------------
class EufyMotionSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Motion"
    _attr_device_class = BinarySensorDeviceClass.MOTION
    _clear_attr = "motion_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "motion")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.motion_detected if d else None


class EufyPersonSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Person Detected"
    _attr_device_class = BinarySensorDeviceClass.MOTION
    _clear_attr = "person_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "person")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.person_detected if d else None


class EufyPetSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Pet Detected"
    _attr_device_class = BinarySensorDeviceClass.MOTION
    _clear_attr = "pet_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "pet")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.pet_detected if d else None


class EufyVehicleSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Vehicle Detected"
    _attr_device_class = BinarySensorDeviceClass.MOTION
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _clear_attr = "vehicle_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "vehicle")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.vehicle_detected if d else None


class EufySoundSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Sound Detected"
    _attr_device_class = BinarySensorDeviceClass.SOUND
    _clear_attr = "sound_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "sound")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.sound_detected if d else None


class EufyCryingSensor(_AutoClearMixin, EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Crying Detected"
    _attr_device_class = BinarySensorDeviceClass.SOUND
    _clear_attr = "crying_detected"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "crying")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.crying_detected if d else None


class EufyRingingSensor(EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Ringing"
    _attr_device_class = BinarySensorDeviceClass.RUNNING

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "ringing")
        self._ringing = False

    @property
    def is_on(self) -> bool:
        return self._ringing

    @callback
    def _handle_coordinator_update(self) -> None:
        super()._handle_coordinator_update()
        data = self.coordinator.data
        if isinstance(data, dict) and "push" in data:
            msg = data["push"]
            if msg.device_sn == self._device_sn and msg.event_type == 3103:
                self._ringing = True
                self.async_write_ha_state()
                self.hass.loop.call_later(10, self._clear_ringing)

    def _clear_ringing(self) -> None:
        self._ringing = False
        self.async_write_ha_state()


class EufyDoorSensor(EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Contact"
    _attr_device_class = BinarySensorDeviceClass.DOOR

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "contact")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.sensor_open if d else None


class EufyBatteryLowSensor(EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Battery Low"
    _attr_device_class = BinarySensorDeviceClass.BATTERY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "battery_low")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        if d and d.battery_level >= 0:
            return d.battery_level <= 15
        return None


class EufyConnectedSensor(EufySecurityEntity, BinarySensorEntity):
    _attr_name = "Connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "connected")

    @property
    def is_on(self) -> bool | None:
        d = self._device
        return d.is_online if d else None


# ---------------------------------------------------------------------------
# Station binary sensors
# ---------------------------------------------------------------------------
class EufyStationConnectedSensor(EufyStationEntity, BinarySensorEntity):
    _attr_name = "Connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "connected")

    @property
    def is_on(self) -> bool:
        return True  # Station is connected if we can reach the cloud
