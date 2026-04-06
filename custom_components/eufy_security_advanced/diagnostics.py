"""Diagnostics support for Eufy Security Advanced.

Provides a downloadable diagnostics dump from the integration page
with sensitive data redacted.
"""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator

REDACTED = "**REDACTED**"
_SENSITIVE_KEYS = {
    "password", "auth_token", "token", "client_private_key",
    "server_public_key", "dsk_key", "private_key", "secret",
    "gcm_token", "security_token",
}


def _redact(data: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive values from a dict."""
    if depth > 10:
        return data
    if isinstance(data, dict):
        return {
            k: REDACTED if any(s in k.lower() for s in _SENSITIVE_KEYS)
            else _redact(v, depth + 1)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact(item, depth + 1) for item in data]
    return data


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]

    stations = {}
    for sn, station in coordinator.stations.items():
        stations[sn] = {
            "name": station.station_name,
            "type": station.device_type.name,
            "guard_mode": station.guard_mode.name,
            "current_mode": station.current_mode.name,
            "ip": station.ip_addr,
            "sw_version": station.main_sw_version,
            "hw_version": station.main_hw_version,
            "p2p_did": REDACTED,
            "devices": station.devices,
            "p2p_connected": (
                coordinator.p2p_pool.is_connected(sn)
                if coordinator.p2p_pool else False
            ),
        }

    devices = {}
    for sn, device in coordinator.devices.items():
        devices[sn] = {
            "name": device.device_name,
            "type": device.device_type.name,
            "model": device.model,
            "station_sn": device.station_sn,
            "channel": device.device_channel,
            "battery": device.battery_level,
            "wifi_rssi": device.wifi_rssi,
            "is_online": device.is_online,
            "sw_version": device.main_sw_version,
            "hw_version": device.main_hw_version,
            "is_camera": device.is_camera,
            "is_doorbell": device.is_doorbell,
            "is_lock": device.is_lock,
            "is_sensor": device.is_sensor,
            "has_battery": device.has_battery,
            "params": device.params,
        }

    stream_info = {}
    if coordinator.stream_manager:
        sm = coordinator.stream_manager
        for d_sn in coordinator.devices:
            if sm.is_streaming(d_sn):
                stream_info[d_sn] = "preemptive_active"

    return {
        "config_entry": _redact(dict(entry.data)),
        "options": dict(entry.options),
        "push_connected": coordinator.push_connected,
        "p2p_connected_stations": (
            coordinator.p2p_pool.connected_stations
            if coordinator.p2p_pool else []
        ),
        "stations": stations,
        "devices": devices,
        "active_streams": stream_info,
    }
