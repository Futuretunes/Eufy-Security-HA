"""Button entities for Eufy Security stations/devices."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufyStationEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        EufyAlarmButton(coordinator, station)
        for station in coordinator.stations.values()
    ]
    async_add_entities(entities)


class EufyAlarmButton(EufyStationEntity, ButtonEntity):
    """Button to trigger the station alarm."""

    _attr_name = "Trigger Alarm"

    def __init__(self, coordinator, station) -> None:
        super().__init__(coordinator, station, "trigger_alarm")

    async def async_press(self) -> None:
        """Trigger the station alarm for 30 seconds."""
        # This will be done via P2P when a session is available.
        # For now, log the intent.
        import logging
        logging.getLogger(__name__).info(
            "Alarm trigger requested for station %s", self._station_sn
        )
