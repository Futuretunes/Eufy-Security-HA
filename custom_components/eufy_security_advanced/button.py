"""Button entities for Eufy Security stations and devices."""

from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity, EufyStationEntity
from .lib.models import DeviceData, StationData
from .lib.p2p.session import P2PSession

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = []

    # Station buttons
    for station in coordinator.stations.values():
        entities.append(EufyAlarmButton(coordinator, station))
        entities.append(EufyAlarmStopButton(coordinator, station))
        entities.append(EufyRebootButton(coordinator, station))

    # Device buttons
    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            entities.append(EufyStartStreamButton(coordinator, device))
            entities.append(EufyStopStreamButton(coordinator, device))
            entities.append(EufyDeviceAlarmButton(coordinator, device))
            entities.append(EufyDeviceAlarmStopButton(coordinator, device))

    async_add_entities(entities)


# ---------------------------------------------------------------------------
# Helper to get a station P2P session
# ---------------------------------------------------------------------------
async def _get_station_session(coordinator: EufySecurityCoordinator, station: StationData) -> P2PSession | None:
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


# ---------------------------------------------------------------------------
# Station buttons
# ---------------------------------------------------------------------------
class EufyAlarmButton(EufyStationEntity, ButtonEntity):
    _attr_name = "Trigger Alarm"
    _attr_icon = "mdi:alarm-light"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "trigger_alarm")

    async def async_press(self) -> None:
        station = self._station
        if not station:
            return
        session = await _get_station_session(self.coordinator, station)
        if not session:
            return
        try:
            nick = self.coordinator.api.persistent_data.nick_name or ""
            await session.trigger_station_alarm(duration=30, nick_name=nick)
        except Exception:
            _LOGGER.exception("Failed to trigger alarm on %s", self._station_sn)
        finally:
            await session.disconnect()


class EufyAlarmStopButton(EufyStationEntity, ButtonEntity):
    _attr_name = "Stop Alarm"
    _attr_icon = "mdi:alarm-light-off"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "stop_alarm")

    async def async_press(self) -> None:
        station = self._station
        if not station:
            return
        session = await _get_station_session(self.coordinator, station)
        if not session:
            return
        try:
            await session.reset_station_alarm()
        except Exception:
            _LOGGER.exception("Failed to stop alarm on %s", self._station_sn)
        finally:
            await session.disconnect()


class EufyRebootButton(EufyStationEntity, ButtonEntity):
    _attr_name = "Reboot"
    _attr_icon = "mdi:restart"
    _attr_entity_category = "config"

    def __init__(self, coordinator, station):
        super().__init__(coordinator, station, "reboot")

    async def async_press(self) -> None:
        _LOGGER.info("Reboot requested for station %s", self._station_sn)
        # Reboot command would be sent via P2P — not all stations support this


# ---------------------------------------------------------------------------
# Device buttons
# ---------------------------------------------------------------------------
class EufyStartStreamButton(EufySecurityEntity, ButtonEntity):
    _attr_name = "Start P2P Stream"
    _attr_icon = "mdi:video"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "start_stream")

    async def async_press(self) -> None:
        device = self._device
        if not device:
            return
        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            return
        session = await _get_station_session(self.coordinator, station)
        if not session:
            return
        try:
            await session.start_livestream(channel=device.device_channel)
            _LOGGER.info("P2P stream started for %s", device.device_sn)
        except Exception:
            _LOGGER.exception("Failed to start stream for %s", device.device_sn)


class EufyStopStreamButton(EufySecurityEntity, ButtonEntity):
    _attr_name = "Stop P2P Stream"
    _attr_icon = "mdi:video-off"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "stop_stream")

    async def async_press(self) -> None:
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            await sm.stop_device(self._device_sn)
            _LOGGER.info("Preemptive stream stopped for %s", self._device_sn)


class EufyDeviceAlarmButton(EufySecurityEntity, ButtonEntity):
    _attr_name = "Trigger Device Alarm"
    _attr_icon = "mdi:alarm-light"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "device_alarm")

    async def async_press(self) -> None:
        device = self._device
        if not device:
            return
        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            return
        session = await _get_station_session(self.coordinator, station)
        if not session:
            return
        try:
            await session.trigger_device_alarm(duration=30, channel=device.device_channel)
        except Exception:
            _LOGGER.exception("Failed to trigger device alarm for %s", device.device_sn)
        finally:
            await session.disconnect()


class EufyDeviceAlarmStopButton(EufySecurityEntity, ButtonEntity):
    _attr_name = "Stop Device Alarm"
    _attr_icon = "mdi:alarm-light-off"

    def __init__(self, coordinator, device):
        super().__init__(coordinator, device, "device_alarm_stop")

    async def async_press(self) -> None:
        device = self._device
        if not device:
            return
        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            return
        session = await _get_station_session(self.coordinator, station)
        if not session:
            return
        try:
            await session.reset_device_alarm(channel=device.device_channel)
        except Exception:
            _LOGGER.exception("Failed to stop device alarm for %s", device.device_sn)
        finally:
            await session.disconnect()
