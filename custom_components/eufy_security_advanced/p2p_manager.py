"""Persistent P2P session pool — one session per station, reused across all operations.

Instead of creating a new P2P session for every command (lock, alarm, stream),
we maintain a persistent session per station. This eliminates the 5-10 second
connection overhead on every action.

Sessions auto-reconnect on disconnect and are cleaned up on integration shutdown.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Callable

from .lib.p2p.session import P2PSession
from .lib.models import StationData

if TYPE_CHECKING:
    from .coordinator import EufySecurityCoordinator

_LOGGER = logging.getLogger(__name__)

# Reconnect delay after unexpected disconnect
_RECONNECT_DELAY = 10
_MAX_RECONNECT_DELAY = 300


class P2PSessionPool:
    """Manages persistent P2P sessions, one per station."""

    def __init__(self, coordinator: EufySecurityCoordinator) -> None:
        self._coordinator = coordinator
        self._sessions: dict[str, P2PSession] = {}  # station_sn -> session
        self._locks: dict[str, asyncio.Lock] = {}    # station_sn -> connect lock
        self._reconnect_tasks: dict[str, asyncio.Task] = {}
        self._reconnect_delays: dict[str, float] = {}
        self._shutting_down = False

    async def get_session(self, station_sn: str) -> P2PSession | None:
        """Get a connected P2P session for a station.

        Returns an existing session if connected, or creates a new one.
        Thread-safe via per-station locks.
        """
        if self._shutting_down:
            return None

        # Get or create lock for this station
        if station_sn not in self._locks:
            self._locks[station_sn] = asyncio.Lock()

        async with self._locks[station_sn]:
            # Return existing connected session
            existing = self._sessions.get(station_sn)
            if existing and existing.connected:
                return existing

            # Create new session
            station = self._coordinator.stations.get(station_sn)
            if not station:
                _LOGGER.warning("Station %s not found in coordinator", station_sn)
                return None

            session = await self._create_session(station)
            if session:
                self._sessions[station_sn] = session
                self._reconnect_delays[station_sn] = _RECONNECT_DELAY
                _LOGGER.info("P2P session pool: connected to %s", station_sn)
            return session

    async def get_session_for_device(self, device_sn: str) -> P2PSession | None:
        """Get a P2P session for a device's station."""
        device = self._coordinator.devices.get(device_sn)
        if not device:
            return None
        return await self.get_session(device.station_sn)

    async def _create_session(self, station: StationData) -> P2PSession | None:
        """Create and connect a new P2P session."""
        try:
            dsk_keys = await self._coordinator.api.get_dsk_keys()
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

            # Set up disconnect handler for auto-reconnect
            session.set_disconnect_callback(
                lambda: self._on_session_disconnect(station.station_sn)
            )

            connected = await session.connect()
            if not connected:
                _LOGGER.warning("P2P connect failed for station %s", station.station_sn)
                return None

            return session

        except Exception:
            _LOGGER.exception("Error creating P2P session for %s", station.station_sn)
            return None

    def _on_session_disconnect(self, station_sn: str) -> None:
        """Handle unexpected session disconnect — clean up, reconnect on next use."""
        self._sessions.pop(station_sn, None)

        if self._shutting_down:
            return

        # Don't auto-reconnect aggressively — it spams DSK key requests
        # that may fail. The next get_session() call will reconnect on demand.
        _LOGGER.info("P2P session ended for %s — will reconnect on next use", station_sn)

    async def _reconnect(self, station_sn: str) -> None:
        """Reconnect to a station with exponential backoff."""
        delay = self._reconnect_delays.get(station_sn, _RECONNECT_DELAY)

        while not self._shutting_down:
            _LOGGER.info("P2P reconnecting to %s in %ds", station_sn, delay)
            await asyncio.sleep(delay)

            if self._shutting_down:
                return

            session = await self.get_session(station_sn)
            if session:
                _LOGGER.info("P2P reconnected to %s", station_sn)
                self._reconnect_delays[station_sn] = _RECONNECT_DELAY
                return

            # Backoff
            delay = min(delay * 2, _MAX_RECONNECT_DELAY)
            self._reconnect_delays[station_sn] = delay

    async def disconnect_station(self, station_sn: str) -> None:
        """Disconnect a specific station's session."""
        task = self._reconnect_tasks.pop(station_sn, None)
        if task and not task.done():
            task.cancel()

        session = self._sessions.pop(station_sn, None)
        if session:
            try:
                await session.disconnect()
            except Exception:
                pass

    async def shutdown(self) -> None:
        """Disconnect all sessions and stop reconnect tasks."""
        self._shutting_down = True

        # Cancel all reconnect tasks
        for task in self._reconnect_tasks.values():
            if not task.done():
                task.cancel()
        self._reconnect_tasks.clear()

        # Disconnect all sessions
        for sn, session in list(self._sessions.items()):
            try:
                await session.disconnect()
            except Exception:
                pass
        self._sessions.clear()

    @property
    def connected_stations(self) -> list[str]:
        """List station SNs with active P2P sessions."""
        return [sn for sn, s in self._sessions.items() if s.connected]

    def is_connected(self, station_sn: str) -> bool:
        """Check if a station has an active P2P session."""
        s = self._sessions.get(station_sn)
        return s is not None and s.connected
