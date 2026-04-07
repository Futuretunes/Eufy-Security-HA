"""Preemptive stream manager — auto-starts/stops P2P streams on push events.

When a relevant event (doorbell press, person detection, motion) arrives via
push notification, the stream manager immediately starts the P2P livestream
for that camera. This eliminates the ~5-10 second connection delay when the
user opens the camera feed.

The stream auto-stops after a configurable timeout to protect battery life.
If a new event arrives while the stream is active, the timeout is extended
(keepalive), so the stream stays up as long as events keep coming.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from .const import (
    CONF_AUTO_START_ON_DOORBELL,
    CONF_AUTO_START_ON_MOTION,
    CONF_AUTO_START_ON_PERSON,
    CONF_AUTO_START_STREAM,
    CONF_STREAM_KEEPALIVE,
    CONF_STREAM_TIMEOUT,
    DEFAULT_AUTO_START_ON_DOORBELL,
    DEFAULT_AUTO_START_ON_MOTION,
    DEFAULT_AUTO_START_ON_PERSON,
    DEFAULT_AUTO_START_STREAM,
    DEFAULT_STREAM_KEEPALIVE,
    DEFAULT_STREAM_TIMEOUT,
)
from .lib.models import DeviceData, PushMessage, StationData
from .lib.p2p.session import P2PSession
from .lib.types import (
    CusPushEvent,
    DoorbellPushEvent,
    IndoorPushEvent,
    RTSP_CAPABLE_TYPES,
)

if TYPE_CHECKING:
    from .coordinator import EufySecurityCoordinator

_LOGGER = logging.getLogger(__name__)

# Push event types that indicate a doorbell press
_DOORBELL_EVENTS = {
    DoorbellPushEvent.PRESS_DOORBELL,
    3103,
}

# Push event types that indicate a person was detected
_PERSON_EVENTS = {
    DoorbellPushEvent.FACE_DETECTION,
    DoorbellPushEvent.FAMILY_DETECTION,
    IndoorPushEvent.FACE,
    3102, 3303,
}

# Push event types that indicate motion was detected
_MOTION_EVENTS = {
    DoorbellPushEvent.MOTION_DETECTION,
    DoorbellPushEvent.RADAR_MOTION_DETECTION,
    IndoorPushEvent.MOTION,
    CusPushEvent.MOTION_SENSOR_PIR,
    3101, 3306,
}


class PreemptiveStreamManager:
    """Manages preemptive P2P stream start/stop based on push events."""

    def __init__(self, coordinator: EufySecurityCoordinator) -> None:
        self._coordinator = coordinator
        self._active_sessions: dict[str, P2PSession] = {}  # device_sn -> session
        self._stop_timers: dict[str, asyncio.TimerHandle] = {}  # device_sn -> timer
        self._stream_active: dict[str, bool] = {}  # device_sn -> is streaming

    @property
    def _options(self) -> dict[str, Any]:
        return self._coordinator.entry.options

    @property
    def _enabled(self) -> bool:
        return self._options.get(CONF_AUTO_START_STREAM, DEFAULT_AUTO_START_STREAM)

    @property
    def _start_on_doorbell(self) -> bool:
        return self._options.get(CONF_AUTO_START_ON_DOORBELL, DEFAULT_AUTO_START_ON_DOORBELL)

    @property
    def _start_on_person(self) -> bool:
        return self._options.get(CONF_AUTO_START_ON_PERSON, DEFAULT_AUTO_START_ON_PERSON)

    @property
    def _start_on_motion(self) -> bool:
        return self._options.get(CONF_AUTO_START_ON_MOTION, DEFAULT_AUTO_START_ON_MOTION)

    @property
    def _timeout(self) -> int:
        return self._options.get(CONF_STREAM_TIMEOUT, DEFAULT_STREAM_TIMEOUT)

    @property
    def _keepalive(self) -> int:
        return self._options.get(CONF_STREAM_KEEPALIVE, DEFAULT_STREAM_KEEPALIVE)

    def is_streaming(self, device_sn: str) -> bool:
        """Check if a device is currently preemptively streaming."""
        return self._stream_active.get(device_sn, False)

    def get_session(self, device_sn: str) -> P2PSession | None:
        """Get the active P2P session for a device (if preemptively started)."""
        session = self._active_sessions.get(device_sn)
        if session and session.connected:
            return session
        return None

    def handle_push_event(self, msg: PushMessage) -> None:
        """Evaluate a push message and start a preemptive stream if appropriate."""
        if not self._enabled:
            return

        device_sn = msg.device_sn
        if not device_sn:
            return

        device = self._coordinator.devices.get(device_sn)
        if not device:
            return

        # Only for cameras and doorbells
        if not (device.is_camera or device.is_doorbell):
            return

        et = msg.event_type
        should_start = False
        reason = ""

        if et in _DOORBELL_EVENTS and self._start_on_doorbell:
            should_start = True
            reason = "doorbell press"
        elif et in _PERSON_EVENTS and self._start_on_person:
            should_start = True
            reason = "person detected"
        elif et in _MOTION_EVENTS and self._start_on_motion:
            should_start = True
            reason = "motion detected"

        if not should_start:
            return

        if self._stream_active.get(device_sn):
            # Already streaming — extend the timeout (keepalive)
            _LOGGER.debug(
                "Stream keepalive for %s (%s), extending by %ds",
                device_sn, reason, self._keepalive,
            )
            self._reschedule_stop(device_sn, self._keepalive)
        else:
            # Start a new preemptive stream
            _LOGGER.info(
                "Preemptive stream start for %s (%s), timeout %ds",
                device_sn, reason, self._timeout,
            )
            asyncio.create_task(self._start_stream(device_sn, device))

    async def _start_stream(self, device_sn: str, device: DeviceData) -> None:
        """Start a preemptive P2P stream for a device."""
        station = self._coordinator.stations.get(device.station_sn)
        if not station:
            _LOGGER.warning("Station %s not found for %s", device.station_sn, device_sn)
            return

        # Don't start if already active
        if self._stream_active.get(device_sn):
            return

        try:
            session = await self._create_session(station)
            if not session:
                return

            self._active_sessions[device_sn] = session
            self._stream_active[device_sn] = True

            # Start the livestream
            started = await session.start_livestream(channel=device.device_channel)
            if not started:
                _LOGGER.warning("Failed to start preemptive stream for %s", device_sn)
                await self._cleanup_device(device_sn)
                return

            _LOGGER.info("Preemptive stream active for %s", device_sn)

            # Schedule auto-stop
            self._reschedule_stop(device_sn, self._timeout)

            # Notify HA that the camera state changed (now streaming)
            self._coordinator.async_set_updated_data(
                {"preemptive_stream_started": device_sn}
            )

        except Exception:
            _LOGGER.exception("Error starting preemptive stream for %s", device_sn)
            await self._cleanup_device(device_sn)

    async def _create_session(self, station: StationData) -> P2PSession | None:
        """Create and connect a P2P session to a station."""
        dsk_keys = await self._coordinator.api.get_dsk_keys(
            station_sns=[station.station_sn]
        )
        dsk_data = dsk_keys.get(station.station_sn, {})
        dsk_key = dsk_data.get("dsk_key", "")

        session = P2PSession(
            station_sn=station.station_sn,
            p2p_did=station.p2p_did,
            dsk_key=dsk_key,
            cloud_ips=station.p2p_cloud_ips or [],
            admin_user_id=self._coordinator.api.persistent_data.user_id,
            get_cipher_callback=self._coordinator.api.get_ciphers,
        )

        connected = await session.connect()
        if not connected:
            _LOGGER.warning("P2P connect failed for station %s", station.station_sn)
            return None
        return session

    def _reschedule_stop(self, device_sn: str, delay: int) -> None:
        """Schedule (or reschedule) the auto-stop timer for a device."""
        # Cancel existing timer
        existing = self._stop_timers.pop(device_sn, None)
        if existing:
            existing.cancel()

        loop = asyncio.get_event_loop()
        handle = loop.call_later(
            delay,
            lambda: asyncio.create_task(self._auto_stop(device_sn)),
        )
        self._stop_timers[device_sn] = handle

    async def _auto_stop(self, device_sn: str) -> None:
        """Auto-stop a preemptive stream after timeout."""
        _LOGGER.info("Auto-stopping preemptive stream for %s (timeout)", device_sn)
        await self._cleanup_device(device_sn)

        self._coordinator.async_set_updated_data(
            {"preemptive_stream_stopped": device_sn}
        )

    async def _cleanup_device(self, device_sn: str) -> None:
        """Stop and clean up a device's preemptive stream."""
        self._stream_active.pop(device_sn, None)

        timer = self._stop_timers.pop(device_sn, None)
        if timer:
            timer.cancel()

        session = self._active_sessions.pop(device_sn, None)
        if session:
            try:
                device = self._coordinator.devices.get(device_sn)
                channel = device.device_channel if device else 0
                if session.is_streaming:
                    await session.stop_livestream(channel=channel)
                await session.disconnect()
            except Exception:
                _LOGGER.debug("Error cleaning up stream for %s", device_sn, exc_info=True)

    async def stop_all(self) -> None:
        """Stop all active preemptive streams (called on integration shutdown)."""
        device_sns = list(self._active_sessions.keys())
        for sn in device_sns:
            await self._cleanup_device(sn)

    async def stop_device(self, device_sn: str) -> None:
        """Manually stop a device's preemptive stream."""
        await self._cleanup_device(device_sn)
