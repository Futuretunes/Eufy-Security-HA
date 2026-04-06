"""Eufy Security Advanced — Home Assistant integration."""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [
    "alarm_control_panel",
    "binary_sensor",
    "button",
    "camera",
    "image",
    "lock",
    "number",
    "select",
    "sensor",
    "switch",
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Eufy Security Advanced from a config entry."""
    coordinator = EufySecurityCoordinator(hass, entry)

    try:
        await coordinator.async_setup()
    except Exception:
        _LOGGER.exception("Failed to set up Eufy Security")
        return False

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register cleanup
    entry.async_on_unload(coordinator.async_shutdown)

    # Reload on options change (stream timeout, auto-start settings, etc.)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))

    return True


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the integration when options are changed."""
    _LOGGER.info("Options updated, reloading Eufy Security Advanced")
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN].get(entry.entry_id)
    if coordinator:
        await coordinator.async_shutdown()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
