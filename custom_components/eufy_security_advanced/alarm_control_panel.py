"""Alarm control panel for Eufy Security stations (guard mode)."""

from __future__ import annotations

import logging

from homeassistant.components.alarm_control_panel import (
    AlarmControlPanelEntity,
    AlarmControlPanelEntityFeature,
    AlarmControlPanelState,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufyStationEntity
from .lib.types import GuardMode

_LOGGER = logging.getLogger(__name__)

GUARD_TO_HA = {
    GuardMode.AWAY: AlarmControlPanelState.ARMED_AWAY,
    GuardMode.HOME: AlarmControlPanelState.ARMED_HOME,
    GuardMode.SCHEDULE: AlarmControlPanelState.ARMED_NIGHT,
    GuardMode.CUSTOM1: AlarmControlPanelState.ARMED_CUSTOM_BYPASS,
    GuardMode.CUSTOM2: AlarmControlPanelState.ARMED_CUSTOM_BYPASS,
    GuardMode.CUSTOM3: AlarmControlPanelState.ARMED_CUSTOM_BYPASS,
    GuardMode.OFF: AlarmControlPanelState.DISARMED,
    GuardMode.DISARMED: AlarmControlPanelState.DISARMED,
    GuardMode.GEO: AlarmControlPanelState.ARMED_AWAY,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        EufyAlarmPanel(coordinator, station)
        for station in coordinator.stations.values()
    ]
    async_add_entities(entities)


class EufyAlarmPanel(EufyStationEntity, AlarmControlPanelEntity):
    """Alarm control panel representing a station's guard mode."""

    _attr_name = "Guard Mode"
    _attr_supported_features = (
        AlarmControlPanelEntityFeature.ARM_HOME
        | AlarmControlPanelEntityFeature.ARM_AWAY
        | AlarmControlPanelEntityFeature.ARM_NIGHT
        | AlarmControlPanelEntityFeature.ARM_CUSTOM_BYPASS
    )
    _attr_code_arm_required = False

    def __init__(self, coordinator: EufySecurityCoordinator, station) -> None:
        super().__init__(coordinator, station, "alarm_panel")

    @property
    def alarm_state(self) -> AlarmControlPanelState | None:
        station = self._station
        if station is None:
            return None
        mode = station.current_mode if station.current_mode != GuardMode.UNKNOWN else station.guard_mode
        return GUARD_TO_HA.get(mode, AlarmControlPanelState.DISARMED)

    async def async_alarm_disarm(self, code: str | None = None) -> None:
        await self.coordinator.api.set_guard_mode(self._station_sn, GuardMode.DISARMED)
        if self._station:
            self._station.guard_mode = GuardMode.DISARMED
            self._station.current_mode = GuardMode.DISARMED
        self.async_write_ha_state()

    async def async_alarm_arm_home(self, code: str | None = None) -> None:
        await self.coordinator.api.set_guard_mode(self._station_sn, GuardMode.HOME)
        if self._station:
            self._station.guard_mode = GuardMode.HOME
            self._station.current_mode = GuardMode.HOME
        self.async_write_ha_state()

    async def async_alarm_arm_away(self, code: str | None = None) -> None:
        await self.coordinator.api.set_guard_mode(self._station_sn, GuardMode.AWAY)
        if self._station:
            self._station.guard_mode = GuardMode.AWAY
            self._station.current_mode = GuardMode.AWAY
        self.async_write_ha_state()

    async def async_alarm_arm_night(self, code: str | None = None) -> None:
        await self.coordinator.api.set_guard_mode(self._station_sn, GuardMode.SCHEDULE)
        if self._station:
            self._station.guard_mode = GuardMode.SCHEDULE
            self._station.current_mode = GuardMode.SCHEDULE
        self.async_write_ha_state()

    async def async_alarm_arm_custom_bypass(self, code: str | None = None) -> None:
        await self.coordinator.api.set_guard_mode(self._station_sn, GuardMode.CUSTOM1)
        if self._station:
            self._station.guard_mode = GuardMode.CUSTOM1
            self._station.current_mode = GuardMode.CUSTOM1
        self.async_write_ha_state()
