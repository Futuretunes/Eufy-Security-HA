"""Select entities for Eufy Security device configuration."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
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
    entities: list[SelectEntity] = []

    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyNightVisionSelect(coordinator, device))
            entities.append(EufyVideoQualitySelect(coordinator, device))
            entities.append(EufyRecordingQualitySelect(coordinator, device))
            entities.append(EufyMotionSensitivitySelect(coordinator, device))
            entities.append(EufySpeakerVolumeSelect(coordinator, device))
            entities.append(EufyWatermarkSelect(coordinator, device))

        if device.has_battery:
            entities.append(EufyPowerSourceSelect(coordinator, device))
            entities.append(EufyPowerModeSelect(coordinator, device))

    for station in coordinator.stations.values():
        entities.append(EufyAlarmVolumeSelect(coordinator, station))

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Helper base
# ---------------------------------------------------------------------------
class _DeviceSelect(EufySecurityEntity, SelectEntity):
    _param_type: int = 0
    _value_map: dict[str, str] = {}
    _attr_entity_category = EntityCategory.CONFIG

    @property
    def current_option(self) -> str | None:
        d = self._device
        if d:
            val = str(d.get_param(self._param_type, ""))
            for name, v in self._value_map.items():
                if v == val:
                    return name
        return None

    @property
    def options(self) -> list[str]:
        return list(self._value_map.keys())

    async def async_select_option(self, option: str) -> None:
        d = self._device
        if not d:
            return
        val = self._value_map.get(option, "")
        await self.coordinator.api.set_device_params(
            d.device_sn, d.station_sn,
            [{"param_type": self._param_type, "param_value": val}],
        )
        d.update_param(self._param_type, val)
        self.async_write_ha_state()


# ---------------------------------------------------------------------------
# Device selects
# ---------------------------------------------------------------------------
class EufyNightVisionSelect(_DeviceSelect):
    _attr_name = "Night Vision"
    _attr_icon = "mdi:weather-night"
    _param_type = ParamType.NIGHT_VISUAL
    _value_map = {"Off": "0", "Auto": "1", "On": "2"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "night_vision")


class EufyVideoQualitySelect(_DeviceSelect):
    _attr_name = "Video Streaming Quality"
    _attr_icon = "mdi:video"
    _param_type = 2015  # videoStreamingQuality
    _value_map = {"Low": "0", "Medium": "1", "High": "2", "Full HD": "3"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "video_quality")


class EufyRecordingQualitySelect(_DeviceSelect):
    _attr_name = "Video Recording Quality"
    _attr_icon = "mdi:video-box"
    _param_type = 2024  # videoRecordingQuality
    _value_map = {"Low": "0", "Medium": "1", "High": "2", "Full HD": "3"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "recording_quality")


class EufyMotionSensitivitySelect(_DeviceSelect):
    _attr_name = "Motion Sensitivity"
    _attr_icon = "mdi:motion-sensor"
    _param_type = ParamType.DETECT_MOTION_SENSITIVE
    _value_map = {
        "1 (Low)": "1", "2": "2", "3": "3", "4 (Medium)": "4",
        "5": "5", "6": "6", "7 (High)": "7",
    }

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "motion_sensitivity")


class EufySpeakerVolumeSelect(_DeviceSelect):
    _attr_name = "Speaker Volume"
    _attr_icon = "mdi:volume-high"
    _param_type = ParamType.CAMERA_SPEAKER_VOLUME
    _value_map = {
        "Mute": "0", "Low": "30", "Medium": "60", "High": "80", "Max": "100",
    }

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "speaker_volume")


class EufyWatermarkSelect(_DeviceSelect):
    _attr_name = "Watermark"
    _attr_icon = "mdi:watermark"
    _param_type = ParamType.WATERMARK_MODE
    _value_map = {"Off": "1", "On": "2"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "watermark")


class EufyPowerSourceSelect(_DeviceSelect):
    _attr_name = "Power Source"
    _attr_icon = "mdi:power-plug"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _param_type = 2046  # powerSource
    _value_map = {"Battery": "0", "Solar Panel": "1", "Plugged In": "2"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "power_source")


class EufyPowerModeSelect(_DeviceSelect):
    _attr_name = "Power Working Mode"
    _attr_icon = "mdi:battery-clock"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _param_type = 2047  # powerWorkingMode
    _value_map = {"Optimal Battery Life": "0", "Optimal Surveillance": "1", "Custom Recording": "2"}

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "power_mode")


# ---------------------------------------------------------------------------
# Station selects
# ---------------------------------------------------------------------------
class EufyAlarmVolumeSelect(EufyStationEntity, SelectEntity):
    _attr_name = "Alarm Volume"
    _attr_icon = "mdi:volume-high"
    _attr_entity_category = EntityCategory.CONFIG

    _value_map = {
        "Mute": "0", "Low": "1", "Medium": "2", "High": "3",
    }

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "alarm_volume")

    @property
    def options(self) -> list[str]:
        return list(self._value_map.keys())

    @property
    def current_option(self) -> str | None:
        s = self._station
        if s:
            val = str(s.raw.get("alarm_volume", ""))
            for name, v in self._value_map.items():
                if v == val:
                    return name
        return None

    async def async_select_option(self, option: str) -> None:
        s = self._station
        if not s:
            return
        val = self._value_map.get(option, "2")
        await self.coordinator.api.set_device_params(
            s.station_sn, s.station_sn,
            [{"param_type": 1260, "param_value": val}],
        )
        self.async_write_ha_state()
