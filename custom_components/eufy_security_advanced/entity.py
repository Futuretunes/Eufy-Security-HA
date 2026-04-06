"""Base entity for Eufy Security Advanced."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import EufySecurityCoordinator
from .lib.models import DeviceData, StationData


class EufySecurityEntity(CoordinatorEntity[EufySecurityCoordinator]):
    """Base class for Eufy Security entities backed by a device."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EufySecurityCoordinator,
        device: DeviceData,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._device_sn = device.device_sn
        self._attr_unique_id = f"{device.device_sn}_{key}"

    @property
    def _device(self) -> DeviceData | None:
        return self.coordinator.devices.get(self._device_sn)

    @property
    def device_info(self) -> DeviceInfo:
        device = self._device
        name = device.device_name if device else self._device_sn
        model = device.model if device else None
        sw = device.main_sw_version if device else None
        hw = device.main_hw_version if device else None
        return DeviceInfo(
            identifiers={(DOMAIN, self._device_sn)},
            name=name,
            manufacturer=MANUFACTURER,
            model=model,
            sw_version=sw,
            hw_version=hw,
        )

    @property
    def available(self) -> bool:
        device = self._device
        if device is None:
            return False
        return super().available


class EufyStationEntity(CoordinatorEntity[EufySecurityCoordinator]):
    """Base class for Eufy Security entities backed by a station."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: EufySecurityCoordinator,
        station: StationData,
        key: str,
    ) -> None:
        super().__init__(coordinator)
        self._station_sn = station.station_sn
        self._attr_unique_id = f"{station.station_sn}_{key}"

    @property
    def _station(self) -> StationData | None:
        return self.coordinator.stations.get(self._station_sn)

    @property
    def device_info(self) -> DeviceInfo:
        station = self._station
        name = station.station_name if station else self._station_sn
        model = station.model if station else None
        sw = station.main_sw_version if station else None
        hw = station.main_hw_version if station else None
        return DeviceInfo(
            identifiers={(DOMAIN, self._station_sn)},
            name=name,
            manufacturer=MANUFACTURER,
            model=model,
            sw_version=sw,
            hw_version=hw,
        )
