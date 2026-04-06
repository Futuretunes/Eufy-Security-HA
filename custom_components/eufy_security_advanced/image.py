"""Image entities for Eufy Security event thumbnails."""

from __future__ import annotations

from datetime import datetime

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
from .lib.models import DeviceData


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        EufyEventImage(coordinator, device)
        for device in coordinator.devices.values()
        if device.is_camera or device.is_doorbell
    ]
    async_add_entities(entities)


class EufyEventImage(EufySecurityEntity, ImageEntity):
    """Last event thumbnail image."""

    _attr_name = "Last Event"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        EufySecurityEntity.__init__(self, coordinator, device, "last_event_image")
        ImageEntity.__init__(self, coordinator.hass)
        self._last_url: str = ""

    @property
    def image_url(self) -> str | None:
        device = self._device
        if device and device.last_event_pic_url:
            if device.last_event_pic_url != self._last_url:
                self._last_url = device.last_event_pic_url
                self._attr_image_last_updated = datetime.now()
            return device.last_event_pic_url
        return None
