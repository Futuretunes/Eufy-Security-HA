"""Switch entities for Eufy Security device toggles."""

from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
from .lib.models import DeviceData
from .lib.types import ParamType

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SwitchEntity] = []

    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyDeviceSwitch(coordinator, device))
            entities.append(EufyMotionDetectionSwitch(coordinator, device))
            entities.append(EufyLedSwitch(coordinator, device))

    async_add_entities(entities)


class EufyParamSwitch(EufySecurityEntity, SwitchEntity):
    """Base switch that toggles a device parameter."""

    _param_type: int = 0
    _on_value: str = "1"
    _off_value: str = "0"

    @property
    def is_on(self) -> bool | None:
        device = self._device
        if device:
            val = device.get_param(self._param_type)
            if val is not None:
                return str(val) == self._on_value
        return None

    async def async_turn_on(self, **kwargs) -> None:
        device = self._device
        if not device:
            return
        await self.coordinator.api.set_device_params(
            device.device_sn,
            device.station_sn,
            [{"param_type": self._param_type, "param_value": self._on_value}],
        )
        device.update_param(self._param_type, self._on_value)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        device = self._device
        if not device:
            return
        await self.coordinator.api.set_device_params(
            device.device_sn,
            device.station_sn,
            [{"param_type": self._param_type, "param_value": self._off_value}],
        )
        device.update_param(self._param_type, self._off_value)
        self.async_write_ha_state()


class EufyDeviceSwitch(EufyParamSwitch):
    """Enable/disable device."""

    _attr_name = "Enabled"
    _param_type = ParamType.OPEN_DEVICE

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "enabled")


class EufyMotionDetectionSwitch(EufyParamSwitch):
    """Motion detection toggle."""

    _attr_name = "Motion Detection"
    _param_type = ParamType.DETECT_SWITCH

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "motion_detection")


class EufyLedSwitch(EufyParamSwitch):
    """Status LED toggle."""

    _attr_name = "Status LED"
    _attr_entity_category = "config"
    _param_type = ParamType.NIGHT_VISUAL
    _on_value = "1"
    _off_value = "0"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        super().__init__(coordinator, device, "led")
