"""Button entities for Eufy Security stations/devices."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufyStationEntity
from .lib.models import StationData

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = []
    for station in coordinator.stations.values():
        entities.append(EufyAlarmButton(coordinator, station))
        entities.append(EufyAlarmStopButton(coordinator, station))
    async_add_entities(entities)


class _StationP2PMixin:
    """Mixin to establish a P2P session to a station for button actions."""

    async def _get_station_session(self):
        from .lib.p2p.session import P2PSession

        station = self._station
        if not station:
            return None

        coordinator = self.coordinator
        dsk_keys = await coordinator.api.get_dsk_keys()
        dsk_data = dsk_keys.get(station.station_sn, {})
        dsk_key = dsk_data.get("dsk_key", "")

        session = P2PSession(
            station_sn=station.station_sn,
            p2p_did=station.p2p_did,
            dsk_key=dsk_key,
            cloud_ips=station.p2p_cloud_ips or [],
            admin_user_id=coordinator.api.persistent_data.user_id,
            get_cipher_callback=coordinator.api.get_ciphers,
        )

        if await session.connect():
            return session
        _LOGGER.error("Failed to connect P2P for station %s", station.station_sn)
        return None


class EufyAlarmButton(_StationP2PMixin, EufyStationEntity, ButtonEntity):
    """Button to trigger the station alarm for 30 seconds."""

    _attr_name = "Trigger Alarm"

    def __init__(self, coordinator: EufySecurityCoordinator, station: StationData) -> None:
        super().__init__(coordinator, station, "trigger_alarm")

    async def async_press(self) -> None:
        session = await self._get_station_session()
        if not session:
            return
        try:
            nick = self.coordinator.api.persistent_data.nick_name or ""
            await session.trigger_station_alarm(duration=30, nick_name=nick)
            _LOGGER.info("Alarm triggered on station %s", self._station_sn)
        except Exception:
            _LOGGER.exception("Failed to trigger alarm on %s", self._station_sn)
        finally:
            await session.disconnect()


class EufyAlarmStopButton(_StationP2PMixin, EufyStationEntity, ButtonEntity):
    """Button to stop the station alarm."""

    _attr_name = "Stop Alarm"

    def __init__(self, coordinator: EufySecurityCoordinator, station: StationData) -> None:
        super().__init__(coordinator, station, "stop_alarm")

    async def async_press(self) -> None:
        session = await self._get_station_session()
        if not session:
            return
        try:
            await session.reset_station_alarm()
            _LOGGER.info("Alarm stopped on station %s", self._station_sn)
        except Exception:
            _LOGGER.exception("Failed to stop alarm on %s", self._station_sn)
        finally:
            await session.disconnect()
