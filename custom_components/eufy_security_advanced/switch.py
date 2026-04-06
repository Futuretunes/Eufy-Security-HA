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
            entities.append(EufyPersonDetectionSwitch(coordinator, device))
            entities.append(EufyPetDetectionSwitch(coordinator, device))
            entities.append(EufyAutoNightvisionSwitch(coordinator, device))
            entities.append(EufyStatusLedSwitch(coordinator, device))
            entities.append(EufyAudioRecordingSwitch(coordinator, device))
            entities.append(EufyMicrophoneSwitch(coordinator, device))
            entities.append(EufySpeakerSwitch(coordinator, device))
            entities.append(EufyAntitheftSwitch(coordinator, device))

        if device.is_doorbell:
            entities.append(EufyChimeIndoorSwitch(coordinator, device))
            entities.append(EufyCryingDetectionSwitch(coordinator, device))

    async_add_entities(entities)


class _ParamSwitch(EufySecurityEntity, SwitchEntity):
    """Base switch that toggles a device parameter via the cloud API."""

    _param_type: int = 0
    _on_value: str = "1"
    _off_value: str = "0"
    _attr_entity_category = "config"

    @property
    def is_on(self) -> bool | None:
        d = self._device
        if d:
            val = d.get_param(self._param_type)
            if val is not None:
                return str(val) == self._on_value
        return None

    async def async_turn_on(self, **kwargs) -> None:
        d = self._device
        if not d:
            return
        await self.coordinator.api.set_device_params(
            d.device_sn, d.station_sn,
            [{"param_type": self._param_type, "param_value": self._on_value}],
        )
        d.update_param(self._param_type, self._on_value)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        d = self._device
        if not d:
            return
        await self.coordinator.api.set_device_params(
            d.device_sn, d.station_sn,
            [{"param_type": self._param_type, "param_value": self._off_value}],
        )
        d.update_param(self._param_type, self._off_value)
        self.async_write_ha_state()


class EufyDeviceSwitch(_ParamSwitch):
    _attr_name = "Enabled"
    _param_type = ParamType.OPEN_DEVICE
    _attr_entity_category = None  # Not a config entity

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "enabled")


class EufyMotionDetectionSwitch(_ParamSwitch):
    _attr_name = "Motion Detection"
    _attr_icon = "mdi:motion-sensor"
    _param_type = ParamType.DETECT_SWITCH

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "motion_detection")


class EufyPersonDetectionSwitch(_ParamSwitch):
    _attr_name = "Person Detection"
    _attr_icon = "mdi:account-eye"
    _param_type = 2169  # commonly used for person detection toggle

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "person_detection")


class EufyPetDetectionSwitch(_ParamSwitch):
    _attr_name = "Pet Detection"
    _attr_icon = "mdi:paw"
    _param_type = 2170  # pet detection toggle

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "pet_detection")


class EufyAutoNightvisionSwitch(_ParamSwitch):
    _attr_name = "Auto Nightvision"
    _attr_icon = "mdi:weather-night"
    _param_type = ParamType.NIGHT_VISUAL

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "auto_nightvision")


class EufyStatusLedSwitch(_ParamSwitch):
    _attr_name = "Status LED"
    _attr_icon = "mdi:led-on"
    _param_type = 1045  # status LED param

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "status_led")


class EufyAudioRecordingSwitch(_ParamSwitch):
    _attr_name = "Audio Recording"
    _attr_icon = "mdi:microphone"
    _param_type = ParamType.CAMERA_RECORD_ENABLE_AUDIO

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "audio_recording")


class EufyMicrophoneSwitch(_ParamSwitch):
    _attr_name = "Microphone"
    _attr_icon = "mdi:microphone"
    _param_type = 2044  # microphone on/off

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "microphone")


class EufySpeakerSwitch(_ParamSwitch):
    _attr_name = "Speaker"
    _attr_icon = "mdi:volume-high"
    _param_type = 2045  # speaker on/off

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "speaker")


class EufyAntitheftSwitch(_ParamSwitch):
    _attr_name = "Antitheft Detection"
    _attr_icon = "mdi:shield-alert"
    _param_type = 2029  # antitheft detection

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "antitheft")


class EufyChimeIndoorSwitch(_ParamSwitch):
    _attr_name = "Indoor Chime"
    _attr_icon = "mdi:bell-ring"
    _param_type = 2036  # chime indoor toggle

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "chime_indoor")


class EufyCryingDetectionSwitch(_ParamSwitch):
    _attr_name = "Crying Detection"
    _attr_icon = "mdi:emoticon-cry"
    _param_type = 2171  # crying detection toggle

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "crying_detection")
