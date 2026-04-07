"""Camera platform for Eufy Security devices.

Still image: fetched from Eufy cloud event thumbnail URL.
Live stream: P2P → ffmpeg (H264→mpegts) → TCP loopback → HA stream component.

Stream lifecycle:
  1. Preemptive start via push event (doorbell press / person detected), OR
  2. On-demand start via async_turn_on() (user clicks Turn On).
  When a stream is active, supported_features includes STREAM so the HA
  camera card shows a live view. stream_source() returns the TCP URL lazily.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import signal

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
from .lib.models import DeviceData, StreamData
from .lib.p2p.session import P2PSession
from .lib.types import RTSP_CAPABLE_TYPES, VideoCodec

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: EufySecurityCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = []
    for device in coordinator.devices.values():
        if device.is_camera or device.is_doorbell:
            try:
                entities.append(EufyCamera(coordinator, device))
            except Exception:
                _LOGGER.exception("Failed to create camera entity for %s", device.device_sn)
    async_add_entities(entities)


class EufyCamera(EufySecurityEntity, Camera):
    """Camera entity — still image preview, live stream on demand."""

    _attr_name = "Camera"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        EufySecurityEntity.__init__(self, coordinator, device, "camera")
        Camera.__init__(self)
        self._p2p_session: P2PSession | None = None
        self._last_image: bytes | None = None
        self._ffmpeg_process: asyncio.subprocess.Process | None = None
        self._pipe_w: int | None = None  # write end of os.pipe()
        self._stream_url: str | None = None

    # ----- Feature flags (dynamic) -----

    @property
    def supported_features(self) -> CameraEntityFeature:
        """Include STREAM only when a live stream is available."""
        features = CameraEntityFeature.ON_OFF
        sm = self.coordinator.stream_manager
        if self._stream_url or (sm and sm.is_streaming(self._device_sn)):
            features |= CameraEntityFeature.STREAM
        return features

    @property
    def is_on(self) -> bool:
        return True

    @property
    def is_streaming(self) -> bool:
        return self._stream_url is not None

    @property
    def motion_detection_enabled(self) -> bool:
        d = self._device
        return d.get_param(2027, "1") != "0" if d else True

    # ----- Still image -----

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return latest event thumbnail from Eufy cloud."""
        d = self._device
        if not d or not d.last_event_pic_url:
            return self._last_image

        url = d.last_event_pic_url
        if url.startswith("/"):
            url = f"{self.coordinator.api.persistent_data.api_base}{url}"

        try:
            from homeassistant.helpers.aiohttp_client import async_get_clientsession
            session = async_get_clientsession(self.hass)
            headers = {}
            api = self.coordinator.api
            if api._auth_token:
                headers["X-Auth-Token"] = api._auth_token
            async with session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    if len(data) > 100:
                        self._last_image = data
        except Exception:
            _LOGGER.debug("Image fetch failed for %s", self._device_sn)

        return self._last_image

    # ----- Stream source (lazy setup) -----

    async def stream_source(self) -> str | None:
        """Return stream URL if a live stream is active.

        If the preemptive stream manager has an active session, this sets up
        the ffmpeg pipeline lazily and returns the TCP loopback URL.
        Returns None if no stream is active (HA then falls back to still image).
        """
        if self._stream_url:
            return self._stream_url

        # Check if preemptive stream is running
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            session = sm.get_session(self._device_sn)
            if session:
                await self._setup_ffmpeg(session)
                return self._stream_url

        return None

    # ----- On/Off -----

    async def async_turn_on(self) -> None:
        """Start live stream (user clicks Turn On)."""
        if self._stream_url:
            return

        d = self._device
        if not d:
            return

        # Try RTSP for supported cameras
        if d.device_type in RTSP_CAPABLE_TYPES:
            url = await self._start_rtsp()
            if url:
                self._stream_url = url
                self.async_write_ha_state()
                return

        # P2P + ffmpeg
        await self._start_p2p_stream()
        self.async_write_ha_state()

    async def async_turn_off(self) -> None:
        """Stop live stream."""
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            await sm.stop_device(self._device_sn)

        if self._p2p_session:
            d = self._device
            try:
                await self._p2p_session.stop_livestream(channel=d.device_channel if d else 0)
            except Exception:
                pass
            await self._p2p_session.disconnect()
            self._p2p_session = None

        await self._cleanup_ffmpeg()
        self._stream_url = None
        self.async_write_ha_state()

    # ----- RTSP -----

    async def _start_rtsp(self) -> str | None:
        session = await self._ensure_p2p_session()
        if not session:
            return None
        d = self._device
        ch = d.device_channel if d else 0
        fut: asyncio.Future[str] = self.hass.loop.create_future()

        def on_event(cmd, data):
            if cmd == 1145 and not fut.done():
                url = data if isinstance(data, str) else str(data)
                if "rtsp://" in url:
                    fut.set_result(url)

        session.set_event_callback(on_event)
        try:
            await session.enable_rtsp(channel=ch, enable=True)
            await session.start_rtsp_stream(channel=ch)
            return await asyncio.wait_for(fut, timeout=10)
        except Exception:
            return None

    # ----- P2P + ffmpeg -----

    async def _start_p2p_stream(self) -> None:
        """Start a P2P stream with ffmpeg transcoding."""
        session = await self._ensure_p2p_session()
        if not session:
            return
        d = self._device
        await self._setup_ffmpeg(session)
        if not self._stream_url:
            return
        started = await session.start_livestream(channel=d.device_channel if d else 0)
        if not started:
            await self._cleanup_ffmpeg()

    async def _setup_ffmpeg(self, session: P2PSession) -> None:
        """Set up ffmpeg to transcode P2P H264 data to mpegts via TCP loopback.

        Uses os.pipe() (anonymous kernel pipe) instead of a named pipe to avoid
        deadlocks: ffmpeg creates the TCP listener immediately, then starts
        reading from the pipe once a client (HA) connects.
        """
        if self._stream_url:
            return

        # Create anonymous pipe: ffmpeg reads from pipe_r, we write to pipe_w
        pipe_r, pipe_w = os.pipe()

        # Set write end to non-blocking so the P2P callback never stalls
        flags = fcntl.fcntl(pipe_w, fcntl.F_GETFL)
        fcntl.fcntl(pipe_w, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        port = await self._find_free_port()
        out_url = f"tcp://127.0.0.1:{port}?listen=1"

        self._ffmpeg_process = await asyncio.create_subprocess_exec(
            "ffmpeg", "-hide_banner", "-loglevel", "warning",
            "-fflags", "+genpts+discardcorrupt",
            "-f", "h264", "-i", "pipe:0",
            "-c:v", "copy", "-an",
            "-f", "mpegts", out_url,
            stdin=pipe_r,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        # Close our copy of the read end — ffmpeg inherited it
        os.close(pipe_r)

        self._pipe_w = pipe_w
        self._stream_url = f"tcp://127.0.0.1:{port}"

        _LOGGER.info(
            "ffmpeg stream ready for %s at %s (pid=%d)",
            self._device_sn, self._stream_url,
            self._ffmpeg_process.pid if self._ffmpeg_process.pid else 0,
        )

        def on_data(data: StreamData) -> None:
            """Write P2P video data to the ffmpeg pipe (non-blocking)."""
            if not data.is_video or not data.data:
                return
            if self._pipe_w is None:
                return
            try:
                os.write(self._pipe_w, data.data)
            except BlockingIOError:
                pass  # pipe buffer full, drop frame
            except OSError:
                pass  # pipe broken

        session.set_stream_callback(on_data)
        session.set_disconnect_callback(self._on_disconnect)

    async def _cleanup_ffmpeg(self) -> None:
        """Tear down the ffmpeg process and pipe."""
        if self._pipe_w is not None:
            try:
                os.close(self._pipe_w)
            except OSError:
                pass
            self._pipe_w = None

        if self._ffmpeg_process:
            try:
                self._ffmpeg_process.send_signal(signal.SIGTERM)
                await asyncio.wait_for(self._ffmpeg_process.wait(), timeout=5)
            except Exception:
                try:
                    self._ffmpeg_process.kill()
                except Exception:
                    pass
            self._ffmpeg_process = None

        self._stream_url = None

    # ----- Helpers -----

    async def _ensure_p2p_session(self) -> P2PSession | None:
        if self._p2p_session and self._p2p_session.connected:
            return self._p2p_session
        pool = self.coordinator.p2p_pool
        if pool:
            d = self._device
            if d:
                self._p2p_session = await pool.get_session(d.station_sn)
                return self._p2p_session
        return None

    @staticmethod
    async def _find_free_port() -> int:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def _on_disconnect(self) -> None:
        self._p2p_session = None
        self.hass.async_create_task(self._cleanup_ffmpeg())
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        if self._p2p_session:
            await self._p2p_session.disconnect()
        await self._cleanup_ffmpeg()
