"""Number entities for Eufy Security device configuration."""

from __future__ import annotations

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity, EufyStationEntity
from .lib.models import DeviceData
from .lib.types import ParamType


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[NumberEntity] = []

    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyVolume(coordinator, device))
            entities.append(EufyRecordClipLength(coordinator, device))
            entities.append(EufyRetriggerInterval(coordinator, device))
            entities.append(EufyFloodlightBrightness(coordinator, device))

    for station in coordinator.stations.values():
        entities.append(EufyAlarmDelay(coordinator, station))

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Device numbers
# ---------------------------------------------------------------------------
class _ParamNumber(EufySecurityEntity, NumberEntity):
    _param_type: int = 0
    _attr_entity_category = "config"

    @property
    def native_value(self) -> float | None:
        d = self._device
        if d:
            val = d.get_param(self._param_type)
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        return None

    async def async_set_native_value(self, value: float) -> None:
        d = self._device
        if not d:
            return
        str_val = str(int(value))
        await self.coordinator.api.set_device_params(
            d.device_sn, d.station_sn,
            [{"param_type": self._param_type, "param_value": str_val}],
        )
        d.update_param(self._param_type, str_val)
        self.async_write_ha_state()


class EufyVolume(_ParamNumber):
    _attr_name = "Volume"
    _attr_icon = "mdi:volume-high"
    _attr_native_min_value = 0
    _attr_native_max_value = 100
    _attr_native_step = 1
    _param_type = ParamType.VOLUME

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "volume")


class EufyRecordClipLength(_ParamNumber):
    _attr_name = "Recording Clip Length"
    _attr_icon = "mdi:timer"
    _attr_native_min_value = 5
    _attr_native_max_value = 120
    _attr_native_step = 5
    _attr_native_unit_of_measurement = "s"
    _param_type = ParamType.CAMERA_RECORD_CLIP_LENGTH

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "clip_length")


class EufyRetriggerInterval(_ParamNumber):
    _attr_name = "Retrigger Interval"
    _attr_icon = "mdi:timer-refresh"
    _attr_native_min_value = 0
    _attr_native_max_value = 300
    _attr_native_step = 5
    _attr_native_unit_of_measurement = "s"
    _param_type = ParamType.CAMERA_RECORD_RETRIGGER_INTERVAL

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "retrigger_interval")


class EufyFloodlightBrightness(_ParamNumber):
    _attr_name = "Floodlight Brightness"
    _attr_icon = "mdi:brightness-6"
    _attr_native_min_value = 22
    _attr_native_max_value = 100
    _attr_native_step = 1
    _attr_native_unit_of_measurement = "%"
    _param_type = ParamType.FLOODLIGHT_MANUAL_BRIGHTNESS

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "floodlight_brightness")


# ---------------------------------------------------------------------------
# Station numbers
# ---------------------------------------------------------------------------
class EufyAlarmDelay(EufyStationEntity, NumberEntity):
    _attr_name = "Alarm Delay"
    _attr_icon = "mdi:timer-alert"
    _attr_entity_category = "config"
    _attr_native_min_value = 0
    _attr_native_max_value = 60
    _attr_native_step = 1
    _attr_native_unit_of_measurement = "s"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "alarm_delay")

    @property
    def native_value(self) -> float | None:
        s = self._station
        if s:
            val = s.raw.get("alarm_delay") or s.raw.get("alarmDelay")
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        return None

    async def async_set_native_value(self, value: float) -> None:
        s = self._station
        if not s:
            return
        await self.coordinator.api.set_device_params(
            s.station_sn, s.station_sn,
            [{"param_type": 1258, "param_value": str(int(value))}],
        )
        self.async_write_ha_state()
