"""Camera platform for Eufy Security devices.

Provides:
- Still image preview (latest event thumbnail from cloud)
- Live stream on click (P2P via ffmpeg, or RTSP for supported cameras)
- Preemptive stream support (stream already running when you open the card)
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import tempfile
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
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
    entities = [
        EufyCamera(coordinator, device)
        for device in coordinator.devices.values()
        if device.is_camera or device.is_doorbell
    ]
    async_add_entities(entities)


class EufyCamera(EufySecurityEntity, Camera):
    """Camera entity — shows latest still, streams live on click."""

    _attr_name = "Camera"
    _attr_supported_features = (
        CameraEntityFeature.ON_OFF | CameraEntityFeature.STREAM
    )
    _attr_brand = "Eufy"

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        EufySecurityEntity.__init__(self, coordinator, device, "camera")
        Camera.__init__(self)
        self._p2p_session: P2PSession | None = None
        self._last_image: bytes | None = None
        self._ffmpeg_process: asyncio.subprocess.Process | None = None
        self._ffmpeg_pipe_path: str | None = None
        self._pipe_fd: int | None = None
        self._stream_url: str | None = None
        self._rtsp_url: str | None = None
        self._use_rtsp: bool = False
        self._is_streaming: bool = False

    # ----- HA Camera properties -----

    @property
    def is_streaming(self) -> bool:
        return self._is_streaming

    @property
    def is_on(self) -> bool:
        # Camera is always "on" — showing still images doesn't require streaming.
        # This prevents HA from blocking async_camera_image() with "Camera is off".
        return True

    @property
    def motion_detection_enabled(self) -> bool:
        d = self._device
        return d.get_param(2027, "1") != "0" if d else True

    @property
    def _supports_rtsp(self) -> bool:
        d = self._device
        return d is not None and d.device_type in RTSP_CAPABLE_TYPES

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {}
        d = self._device
        if d:
            if d.last_event_pic_url:
                attrs["last_event_pic_url"] = d.last_event_pic_url
            if d.last_event_time:
                attrs["last_event_time"] = d.last_event_time
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            attrs["stream_mode"] = "preemptive"
        elif self._use_rtsp:
            attrs["stream_mode"] = "rtsp"
        elif self._is_streaming:
            attrs["stream_mode"] = "p2p"
        else:
            attrs["stream_mode"] = "idle"
        return attrs

    # ----- Still image (shown as preview on dashboard) -----

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the latest still image.

        Fetches the most recent event thumbnail from the Eufy cloud.
        This is what shows as the preview in a picture-entity or
        picture-glance card on the Lovelace dashboard.
        """
        d = self._device
        if d and d.last_event_pic_url:
            url = d.last_event_pic_url
            _LOGGER.debug("Fetching camera image for %s from %s", self._device_sn, url[:80])
            try:
                from homeassistant.helpers.aiohttp_client import async_get_clientsession
                session = async_get_clientsession(self.hass)
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        self._last_image = await resp.read()
                        _LOGGER.debug(
                            "Got image for %s: %d bytes",
                            self._device_sn, len(self._last_image),
                        )
                    else:
                        _LOGGER.warning(
                            "Image fetch for %s returned HTTP %d",
                            self._device_sn, resp.status,
                        )
            except Exception:
                _LOGGER.debug("Failed to fetch event image for %s", self._device_sn, exc_info=True)
        else:
            if d:
                _LOGGER.debug("No event pic URL for %s", self._device_sn)
            else:
                _LOGGER.debug("Device %s not found in coordinator", self._device_sn)

        return self._last_image

    # ----- Live stream (opened when user clicks the camera card) -----

    async def stream_source(self) -> str | None:
        """Return the live stream URL for HA's stream integration.

        HA calls this when the user clicks the camera to view the live
        stream. We start the P2P stream on demand here so it works
        automatically — no need to press a separate button first.
        """
        # 1. If preemptive stream is already running, attach to it (instant)
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            session = sm.get_session(self._device_sn)
            if session:
                if not self._stream_url:
                    await self._setup_ffmpeg_pipe(session)
                if self._stream_url:
                    self._is_streaming = True
                    return self._stream_url

        # 2. If already streaming, return the existing URL
        if self._stream_url:
            return self._stream_url

        # 3. Start stream on demand (this is where the live view click triggers)
        _LOGGER.info("Starting on-demand stream for %s", self._device_sn)

        # Try RTSP first
        if self._supports_rtsp:
            url = await self._start_rtsp()
            if url:
                self._rtsp_url = url
                self._use_rtsp = True
                self._stream_url = url
                self._is_streaming = True
                return url

        # Fall back to P2P + ffmpeg
        started = await self._start_p2p_stream()
        if started:
            self._is_streaming = True
            return self._stream_url

        return None

    # ----- On/Off control -----

    async def async_turn_on(self) -> None:
        """Start the camera stream."""
        if self._is_streaming:
            return
        # stream_source() handles starting everything
        await self.stream_source()
        self.async_write_ha_state()

    async def async_turn_off(self) -> None:
        """Stop the camera stream."""
        self._is_streaming = False

        # Stop preemptive stream if running
        sm = self.coordinator.stream_manager
        if sm and sm.is_streaming(self._device_sn):
            await sm.stop_device(self._device_sn)

        if self._use_rtsp:
            await self._stop_rtsp()
        else:
            await self._stop_p2p_stream()

        self._stream_url = None
        self._use_rtsp = False
        self.async_write_ha_state()

    # ----- RTSP -----

    async def _start_rtsp(self) -> str | None:
        """Start RTSP stream via P2P command. Returns RTSP URL or None."""
        session = await self._ensure_p2p_session()
        if not session:
            return None

        d = self._device
        channel = d.device_channel if d else 0
        rtsp_url_future: asyncio.Future[str] = self.hass.loop.create_future()

        def on_event(cmd: int, data: dict) -> None:
            if cmd == 1145 and not rtsp_url_future.done():
                url = data if isinstance(data, str) else str(data)
                if "rtsp://" in url:
                    rtsp_url_future.set_result(url)

        session.set_event_callback(on_event)

        try:
            await session.enable_rtsp(channel=channel, enable=True)
            await session.start_rtsp_stream(channel=channel)
            return await asyncio.wait_for(rtsp_url_future, timeout=10.0)
        except (asyncio.TimeoutError, Exception):
            _LOGGER.debug("RTSP not available for %s, using P2P", self._device_sn)
            return None

    async def _stop_rtsp(self) -> None:
        if self._p2p_session and self._p2p_session.connected:
            d = self._device
            try:
                await self._p2p_session.stop_rtsp_stream(channel=d.device_channel if d else 0)
            except Exception:
                pass
            await self._p2p_session.disconnect()
            self._p2p_session = None
        self._rtsp_url = None

    # ----- P2P + ffmpeg pipeline -----

    async def _start_p2p_stream(self) -> bool:
        """Start P2P livestream, pipe through ffmpeg. Returns True on success."""
        session = await self._ensure_p2p_session()
        if not session:
            return False

        d = self._device
        channel = d.device_channel if d else 0

        await self._setup_ffmpeg_pipe(session)
        if not self._stream_url:
            return False

        started = await session.start_livestream(channel=channel)
        if not started:
            _LOGGER.warning("P2P livestream failed for %s", self._device_sn)
            await self._cleanup_ffmpeg()
            return False

        _LOGGER.info("P2P stream active for %s", self._device_sn)
        return True

    async def _setup_ffmpeg_pipe(self, session: P2PSession) -> None:
        """Set up the named pipe + ffmpeg process to feed HA's stream component."""
        if self._stream_url:
            return  # Already set up

        pipe_dir = tempfile.mkdtemp(prefix="eufy_")
        self._ffmpeg_pipe_path = os.path.join(pipe_dir, "video.pipe")
        os.mkfifo(self._ffmpeg_pipe_path)

        output_port = await self._find_free_port()
        output_url = f"tcp://127.0.0.1:{output_port}?listen=1"
        self._stream_url = f"tcp://127.0.0.1:{output_port}"

        ffmpeg_cmd = [
            "ffmpeg",
            "-hide_banner", "-loglevel", "warning",
            "-fflags", "+genpts+discardcorrupt",
            "-f", "h264",
            "-i", self._ffmpeg_pipe_path,
            "-c:v", "copy",
            "-f", "mpegts",
            output_url,
        ]

        self._ffmpeg_process = await asyncio.create_subprocess_exec(
            *ffmpeg_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        self._pipe_fd = None

        def on_stream_data(data: StreamData) -> None:
            if not data.is_video or not data.data:
                return
            if self._pipe_fd is None:
                try:
                    self._pipe_fd = os.open(
                        self._ffmpeg_pipe_path, os.O_WRONLY | os.O_NONBLOCK
                    )
                except OSError:
                    return
            try:
                os.write(self._pipe_fd, data.data)
            except OSError:
                pass
            self._last_image = data.data

        session.set_stream_callback(on_stream_data)
        session.set_disconnect_callback(self._on_p2p_disconnect)

    async def _stop_p2p_stream(self) -> None:
        if self._p2p_session:
            d = self._device
            try:
                await self._p2p_session.stop_livestream(channel=d.device_channel if d else 0)
            except Exception:
                pass
            await self._p2p_session.disconnect()
            self._p2p_session = None
        await self._cleanup_ffmpeg()

    async def _cleanup_ffmpeg(self) -> None:
        if self._pipe_fd is not None:
            try:
                os.close(self._pipe_fd)
            except OSError:
                pass
            self._pipe_fd = None

        if self._ffmpeg_process:
            try:
                self._ffmpeg_process.send_signal(signal.SIGTERM)
                await asyncio.wait_for(self._ffmpeg_process.wait(), timeout=5.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self._ffmpeg_process.kill()
                except ProcessLookupError:
                    pass
            self._ffmpeg_process = None

        if self._ffmpeg_pipe_path:
            try:
                os.unlink(self._ffmpeg_pipe_path)
                os.rmdir(os.path.dirname(self._ffmpeg_pipe_path))
            except OSError:
                pass
            self._ffmpeg_pipe_path = None

        self._stream_url = None

    # ----- Helpers -----

    async def _ensure_p2p_session(self) -> P2PSession | None:
        if self._p2p_session and self._p2p_session.connected:
            return self._p2p_session

        d = self._device
        if not d:
            return None

        station = self.coordinator.stations.get(d.station_sn)
        if not station:
            _LOGGER.warning("Station %s not found for %s", d.station_sn, d.device_sn)
            return None

        dsk_keys = await self.coordinator.api.get_dsk_keys()
        dsk_data = dsk_keys.get(station.station_sn, {})
        dsk_key = dsk_data.get("dsk_key", "")

        self._p2p_session = P2PSession(
            station_sn=station.station_sn,
            p2p_did=station.p2p_did,
            dsk_key=dsk_key,
            cloud_ips=station.p2p_cloud_ips or [],
            admin_user_id=self.coordinator.api.persistent_data.user_id,
            get_cipher_callback=self.coordinator.api.get_ciphers,
        )

        if not await self._p2p_session.connect():
            _LOGGER.warning("P2P connect failed for %s", d.device_sn)
            self._p2p_session = None
            return None

        return self._p2p_session

    @staticmethod
    async def _find_free_port() -> int:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def _on_p2p_disconnect(self) -> None:
        _LOGGER.debug("P2P disconnected for %s", self._device_sn)
        self._p2p_session = None
        self._is_streaming = False
        self.hass.async_create_task(self._cleanup_ffmpeg())
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        if self._p2p_session:
            await self._p2p_session.disconnect()
        await self._cleanup_ffmpeg()
