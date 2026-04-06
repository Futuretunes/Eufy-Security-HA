"""Number entities for Eufy Security device configuration."""

from __future__ import annotations

from homeassistant.components.number import NumberEntity
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
    entities: list[NumberEntity] = []

    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyVolume(coordinator, device))
            entities.append(EufyMotionSensitivity(coordinator, device))

    async_add_entities(entities)


class EufyParamNumber(EufySecurityEntity, NumberEntity):
    """Base number entity for a device parameter."""

    _param_type: int = 0
    _attr_entity_category = "config"

    @property
    def native_value(self) -> float | None:
        device = self._device
        if device:
            val = device.get_param(self._param_type)
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    pass
        return None

    async def async_set_native_value(self, value: float) -> None:
        device = self._device
        if not device:
            return
        str_val = str(int(value))
        await self.coordinator.api.set_device_params(
            device.device_sn,
            device.station_sn,
            [{"param_type": self._param_type, "param_value": str_val}],
        )
        device.update_param(self._param_type, str_val)
        self.async_write_ha_state()


class EufyVolume(EufyParamNumber):
    """Speaker volume."""

    _attr_name = "Volume"
    _attr_native_min_value = 0
    _attr_native_max_value = 100
    _attr_native_step = 1
    _param_type = ParamType.VOLUME

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "volume")


class EufyMotionSensitivity(EufyParamNumber):
    """Motion detection sensitivity."""

    _attr_name = "Motion Sensitivity"
    _attr_native_min_value = 1
    _attr_native_max_value = 7
    _attr_native_step = 1
    _param_type = ParamType.DETECT_MOTION_SENSITIVE

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "motion_sensitivity")
