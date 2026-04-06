"""Service handlers for Eufy Security Advanced.

Provides PTZ, alarm, talkback, and notification services.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator

_LOGGER = logging.getLogger(__name__)

_DIRECTION_MAP = {"up": 0, "down": 1, "left": 2, "right": 3}


def _get_coordinator(hass: HomeAssistant) -> EufySecurityCoordinator | None:
    """Get the first available coordinator."""
    for coordinator in hass.data.get(DOMAIN, {}).values():
        if isinstance(coordinator, EufySecurityCoordinator):
            return coordinator
    return None


async def async_setup_services(hass: HomeAssistant) -> None:
    """Register all integration services."""

    async def handle_ptz_move(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        device_sn = call.data["device_sn"]
        direction = _DIRECTION_MAP.get(call.data["direction"], 0)
        session = await coordinator.p2p_pool.get_session_for_device(device_sn)
        if session:
            await session.pan_tilt(direction)

    async def handle_ptz_360(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        device_sn = call.data["device_sn"]
        session = await coordinator.p2p_pool.get_session_for_device(device_sn)
        if session:
            await session.pan_tilt(4)  # 4 = 360 rotation

    async def handle_trigger_alarm(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        station_sn = call.data["station_sn"]
        duration = call.data.get("duration", 30)
        session = await coordinator.p2p_pool.get_session(station_sn)
        if session:
            nick = coordinator.api.persistent_data.nick_name or ""
            await session.trigger_station_alarm(duration=duration, nick_name=nick)

    async def handle_stop_alarm(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        station_sn = call.data["station_sn"]
        session = await coordinator.p2p_pool.get_session(station_sn)
        if session:
            await session.reset_station_alarm()

    async def handle_start_talkback(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        device_sn = call.data["device_sn"]
        device = coordinator.devices.get(device_sn)
        if not device:
            return
        session = await coordinator.p2p_pool.get_session(device.station_sn)
        if session:
            await session.start_talkback(
                channel=device.device_channel,
                use_doorbell_cmd=not device.is_doorbell,
            )

    async def handle_stop_talkback(call: ServiceCall) -> None:
        coordinator = _get_coordinator(hass)
        if not coordinator or not coordinator.p2p_pool:
            return
        device_sn = call.data["device_sn"]
        device = coordinator.devices.get(device_sn)
        if not device:
            return
        session = await coordinator.p2p_pool.get_session(device.station_sn)
        if session:
            await session.stop_talkback(
                channel=device.device_channel,
                use_doorbell_cmd=not device.is_doorbell,
            )

    async def handle_send_notification_image(call: ServiceCall) -> None:
        """Send the latest event image as an HA persistent notification."""
        coordinator = _get_coordinator(hass)
        if not coordinator:
            return
        device_sn = call.data["device_sn"]
        title = call.data.get("title", "Eufy Security")
        device = coordinator.devices.get(device_sn)
        if not device or not device.last_event_pic_url:
            _LOGGER.warning("No event image for %s", device_sn)
            return

        await hass.services.async_call(
            "persistent_notification",
            "create",
            {
                "title": title,
                "message": (
                    f"**{device.device_name}**\n\n"
                    f"![Event Image]({device.last_event_pic_url})"
                ),
                "notification_id": f"eufy_{device_sn}_event",
            },
        )

    # Register services
    hass.services.async_register(DOMAIN, "ptz_move", handle_ptz_move)
    hass.services.async_register(DOMAIN, "ptz_360", handle_ptz_360)
    hass.services.async_register(DOMAIN, "trigger_alarm", handle_trigger_alarm)
    hass.services.async_register(DOMAIN, "stop_alarm", handle_stop_alarm)
    hass.services.async_register(DOMAIN, "start_talkback", handle_start_talkback)
    hass.services.async_register(DOMAIN, "stop_talkback", handle_stop_talkback)
    hass.services.async_register(DOMAIN, "send_notification_image", handle_send_notification_image)


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unload all integration services."""
    for service_name in [
        "ptz_move", "ptz_360", "trigger_alarm", "stop_alarm",
        "start_talkback", "stop_talkback", "send_notification_image",
    ]:
        hass.services.async_remove(DOMAIN, service_name)
