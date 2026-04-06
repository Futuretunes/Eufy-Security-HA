"""Select entities for Eufy Security device configuration."""

from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
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
            entities.append(EufyWatermarkSelect(coordinator, device))

    async_add_entities(entities)


NIGHT_VISION_OPTIONS = {
    "Off": "0",
    "Auto": "1",
    "On": "2",
}

WATERMARK_OPTIONS = {
    "Off": "1",
    "On": "2",
}


class EufyNightVisionSelect(EufySecurityEntity, SelectEntity):
    """Night vision mode selection."""

    _attr_name = "Night Vision"
    _attr_options = list(NIGHT_VISION_OPTIONS.keys())
    _attr_entity_category = "config"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "night_vision")

    @property
    def current_option(self) -> str | None:
        device = self._device
        if device:
            val = str(device.get_param(ParamType.NIGHT_VISUAL, "1"))
            for name, v in NIGHT_VISION_OPTIONS.items():
                if v == val:
                    return name
        return None

    async def async_select_option(self, option: str) -> None:
        device = self._device
        if not device:
            return
        val = NIGHT_VISION_OPTIONS.get(option, "1")
        await self.coordinator.api.set_device_params(
            device.device_sn,
            device.station_sn,
            [{"param_type": ParamType.NIGHT_VISUAL, "param_value": val}],
        )
        device.update_param(ParamType.NIGHT_VISUAL, val)
        self.async_write_ha_state()


class EufyWatermarkSelect(EufySecurityEntity, SelectEntity):
    """Watermark mode selection."""

    _attr_name = "Watermark"
    _attr_options = list(WATERMARK_OPTIONS.keys())
    _attr_entity_category = "config"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "watermark")

    @property
    def current_option(self) -> str | None:
        device = self._device
        if device:
            val = str(device.get_param(ParamType.WATERMARK_MODE, "2"))
            for name, v in WATERMARK_OPTIONS.items():
                if v == val:
                    return name
        return None

    async def async_select_option(self, option: str) -> None:
        device = self._device
        if not device:
            return
        val = WATERMARK_OPTIONS.get(option, "2")
        await self.coordinator.api.set_device_params(
            device.device_sn,
            device.station_sn,
            [{"param_type": ParamType.WATERMARK_MODE, "param_value": val}],
        )
        device.update_param(ParamType.WATERMARK_MODE, val)
        self.async_write_ha_state()
