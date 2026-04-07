"""Sensor entities for Eufy Security devices and stations."""

from __future__ import annotations

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity, EufyStationEntity
from .lib.models import DeviceData, StationData
from .lib.types import GuardMode


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SensorEntity] = []

    for device in coordinator.devices.values():
        if device.has_battery:
            entities.append(EufyBatterySensor(coordinator, device))
            entities.append(EufyBatteryTempSensor(coordinator, device))
            entities.append(EufyChargingStatusSensor(coordinator, device))

        if device.is_camera or device.is_doorbell:
            entities.append(EufyWifiSensor(coordinator, device))
            entities.append(EufyWifiSignalLevelSensor(coordinator, device))
            entities.append(EufyLastEventSensor(coordinator, device))
            entities.append(EufyStreamStatusSensor(coordinator, device))

        # Firmware sensor for all devices
        entities.append(EufyFirmwareSensor(coordinator, device))

    # Station sensors
    for station in coordinator.stations.values():
        entities.append(EufyGuardModeSensor(coordinator, station))
        entities.append(EufyCurrentModeSensor(coordinator, station))
        entities.append(EufyStationFirmwareSensor(coordinator, station))

    # Integration-level push status sensor
    entities.append(EufyPushStatusSensor(coordinator))

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Device sensors
# ---------------------------------------------------------------------------
class EufyBatterySensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = "diagnostic"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "battery")

    @property
    def native_value(self) -> int | None:
        d = self._device
        return d.battery_level if d and d.battery_level >= 0 else None


class EufyBatteryTempSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Battery Temperature"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = "diagnostic"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "battery_temp")

    @property
    def native_value(self) -> float | None:
        d = self._device
        if d:
            val = d.raw.get("battery_temperature") or d.raw.get("batteryTemperature")
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        return None


class EufyChargingStatusSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Charging Status"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:battery-charging"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "charging_status")

    @property
    def native_value(self) -> str | None:
        d = self._device
        if d:
            val = d.raw.get("charging_status") or d.raw.get("chargingStatus")
            if val is not None:
                _map = {0: "Not Charging", 1: "Charging", 2: "Solar Charging", 3: "Plugged In"}
                return _map.get(int(val), str(val))
        return None


class EufyWifiSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "WiFi RSSI"
    _attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
    _attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = "diagnostic"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "wifi_rssi")

    @property
    def native_value(self) -> int | None:
        d = self._device
        return d.wifi_rssi if d and d.wifi_rssi != 0 else None


class EufyWifiSignalLevelSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "WiFi Signal Level"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:wifi"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "wifi_signal_level")

    @property
    def native_value(self) -> str | None:
        d = self._device
        if d and d.wifi_rssi != 0:
            rssi = d.wifi_rssi
            if rssi >= -50:
                return "Excellent"
            if rssi >= -60:
                return "Good"
            if rssi >= -70:
                return "Fair"
            return "Poor"
        return None


class EufyLastEventSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Last Event"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:history"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "last_event")

    @property
    def native_value(self) -> str | None:
        d = self._device
        if d and d.last_event_time:
            from datetime import datetime, timezone
            try:
                dt = datetime.fromtimestamp(d.last_event_time, tz=timezone.utc)
                return dt.isoformat()
            except (OSError, ValueError):
                pass
        return None


class EufyStreamStatusSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Stream Status"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:video"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "stream_status")

    @property
    def native_value(self) -> str:
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            return "Preemptive"
        d = self._device
        if d and d.is_streaming:
            return "Active"
        return "Idle"


# ---------------------------------------------------------------------------
# Station sensors
# ---------------------------------------------------------------------------
_GUARD_MODE_NAMES = {
    GuardMode.AWAY: "Away",
    GuardMode.HOME: "Home",
    GuardMode.SCHEDULE: "Schedule",
    GuardMode.CUSTOM1: "Custom 1",
    GuardMode.CUSTOM2: "Custom 2",
    GuardMode.CUSTOM3: "Custom 3",
    GuardMode.OFF: "Off",
    GuardMode.GEO: "Geofence",
    GuardMode.DISARMED: "Disarmed",
    GuardMode.UNKNOWN: "Unknown",
}


class EufyGuardModeSensor(EufyStationEntity, SensorEntity):
    _attr_name = "Guard Mode"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:security"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "guard_mode")

    @property
    def native_value(self) -> str:
        s = self._station
        if s:
            return _GUARD_MODE_NAMES.get(s.guard_mode, str(s.guard_mode.value))
        return "Unknown"


class EufyCurrentModeSensor(EufyStationEntity, SensorEntity):
    _attr_name = "Current Mode"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:security"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "current_mode")

    @property
    def native_value(self) -> str:
        s = self._station
        if s:
            return _GUARD_MODE_NAMES.get(s.current_mode, str(s.current_mode.value))
        return "Unknown"


class EufyStationFirmwareSensor(EufyStationEntity, SensorEntity):
    _attr_name = "Firmware"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:update"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "firmware")

    @property
    def native_value(self) -> str | None:
        s = self._station
        return s.main_sw_version if s else None


# ---------------------------------------------------------------------------
# Device firmware sensor
# ---------------------------------------------------------------------------
class EufyFirmwareSensor(EufySecurityEntity, SensorEntity):
    _attr_name = "Firmware"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:update"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "firmware")

    @property
    def native_value(self) -> str | None:
        d = self._device
        return d.main_sw_version if d else None


# ---------------------------------------------------------------------------
# Integration-level push status sensor
# ---------------------------------------------------------------------------
class EufyPushStatusSensor(SensorEntity):
    """Shows whether FCM push notifications are connected."""

    _attr_has_entity_name = False
    _attr_name = "Eufy Security Push Status"
    _attr_entity_category = "diagnostic"
    _attr_icon = "mdi:bell-ring"

    def __init__(self, coordinator) -> None:
        self.coordinator = coordinator
        self._attr_unique_id = f"{DOMAIN}_push_status"

    @property
    def native_value(self) -> str:
        return "Connected" if self.coordinator.push_connected else "Disconnected"
