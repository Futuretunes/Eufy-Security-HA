"""Camera platform for Eufy Security devices with P2P streaming and RTSP fallback."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import tempfile
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.components.stream import Stream
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
    entities = [
        EufyCamera(coordinator, device)
        for device in coordinator.devices.values()
        if device.is_camera or device.is_doorbell
    ]
    async_add_entities(entities)


class EufyCamera(EufySecurityEntity, Camera):
    """Camera entity with P2P livestream + ffmpeg pipeline and RTSP fallback."""

    _attr_name = "Camera"
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        EufySecurityEntity.__init__(self, coordinator, device, "camera")
        Camera.__init__(self)
        self._p2p_session: P2PSession | None = None
        self._last_image: bytes | None = None
        self._ffmpeg_process: asyncio.subprocess.Process | None = None
        self._ffmpeg_pipe_path: str | None = None
        self._stream_source: str | None = None
        self._rtsp_url: str | None = None
        self._use_rtsp: bool = False

    @property
    def is_streaming(self) -> bool:
        return self._p2p_session is not None and self._p2p_session.is_streaming

    @property
    def motion_detection_enabled(self) -> bool:
        device = self._device
        if device:
            return device.get_param(2027, "1") != "0"
        return True

    @property
    def _supports_rtsp(self) -> bool:
        device = self._device
        return device is not None and device.device_type in RTSP_CAPABLE_TYPES

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """Return the last captured image."""
        device = self._device
        if device and device.last_event_pic_url:
            try:
                from homeassistant.helpers.aiohttp_client import async_get_clientsession
                session = async_get_clientsession(self.hass)
                async with session.get(device.last_event_pic_url) as resp:
                    if resp.status == 200:
                        self._last_image = await resp.read()
            except Exception:
                _LOGGER.debug("Failed to fetch event image", exc_info=True)
        return self._last_image

    async def stream_source(self) -> str | None:
        """Return the stream source URL for HA's stream integration.

        Returns an RTSP URL for RTSP-capable cameras, or a named pipe URL
        fed by ffmpeg for P2P-only cameras.
        """
        # Prefer RTSP if available and configured
        if self._use_rtsp and self._rtsp_url:
            return self._rtsp_url

        if self._stream_source:
            return self._stream_source

        return None

    async def async_turn_on(self) -> None:
        """Start the livestream — tries RTSP first, falls back to P2P+ffmpeg."""
        device = self._device
        if not device:
            return

        # Try RTSP first for supported cameras
        if self._supports_rtsp:
            rtsp_url = await self._start_rtsp()
            if rtsp_url:
                self._rtsp_url = rtsp_url
                self._use_rtsp = True
                self._stream_source = rtsp_url
                _LOGGER.info("Using RTSP stream for %s: %s", device.device_sn, rtsp_url)
                self.async_write_ha_state()
                return

        # Fall back to P2P + ffmpeg pipeline
        await self._start_p2p_stream()

    async def async_turn_off(self) -> None:
        """Stop the livestream."""
        if self._use_rtsp:
            await self._stop_rtsp()
        else:
            await self._stop_p2p_stream()

        self._stream_source = None
        self._use_rtsp = False
        self.async_write_ha_state()

    # ----- RTSP -----

    async def _start_rtsp(self) -> str | None:
        """Start RTSP stream via P2P command. Returns RTSP URL or None."""
        session = await self._ensure_p2p_session()
        if not session:
            return None

        device = self._device
        channel = device.device_channel if device else 0
        rtsp_url_future: asyncio.Future[str] = asyncio.get_event_loop().create_future()

        def on_event(cmd: int, data: dict) -> None:
            # The device responds to CMD_NAS_TEST with a CMD_NAS_SWITCH
            # containing the RTSP URL
            if cmd == 1145 and not rtsp_url_future.done():
                # data might be raw bytes decoded to string
                url = data if isinstance(data, str) else str(data)
                if url.startswith("rtsp://"):
                    rtsp_url_future.set_result(url)

        session.set_event_callback(on_event)

        try:
            await session.enable_rtsp(channel=channel, enable=True)
            await session.start_rtsp_stream(channel=channel)
            url = await asyncio.wait_for(rtsp_url_future, timeout=10.0)
            return url
        except asyncio.TimeoutError:
            _LOGGER.debug("RTSP URL not received for %s, falling back to P2P", self._device_sn)
            return None
        except Exception:
            _LOGGER.debug("RTSP start failed for %s", self._device_sn, exc_info=True)
            return None

    async def _stop_rtsp(self) -> None:
        """Stop RTSP stream."""
        if self._p2p_session and self._p2p_session.connected:
            device = self._device
            channel = device.device_channel if device else 0
            try:
                await self._p2p_session.stop_rtsp_stream(channel=channel)
            except Exception:
                pass
            await self._p2p_session.disconnect()
            self._p2p_session = None
        self._rtsp_url = None

    # ----- P2P + ffmpeg pipeline -----

    async def _start_p2p_stream(self) -> None:
        """Start P2P livestream and pipe through ffmpeg to create a stream source."""
        session = await self._ensure_p2p_session()
        if not session:
            return

        device = self._device
        channel = device.device_channel if device else 0

        # Create a named pipe for ffmpeg input
        pipe_dir = tempfile.mkdtemp(prefix="eufy_")
        self._ffmpeg_pipe_path = os.path.join(pipe_dir, "video.pipe")
        os.mkfifo(self._ffmpeg_pipe_path)

        # Output: TCP socket that HA's stream component can read
        output_port = await self._find_free_port()
        output_url = f"tcp://127.0.0.1:{output_port}?listen=1"
        self._stream_source = f"tcp://127.0.0.1:{output_port}"

        # Determine codec for ffmpeg input
        video_codec = "h264"  # default, will be detected

        # Start ffmpeg: read from named pipe, output MPEGTS over TCP
        ffmpeg_cmd = [
            "ffmpeg",
            "-hide_banner", "-loglevel", "warning",
            "-fflags", "+genpts+discardcorrupt",
            "-f", video_codec,
            "-i", self._ffmpeg_pipe_path,
            "-c:v", "copy",
            "-f", "mpegts",
            output_url,
        ]

        _LOGGER.debug("Starting ffmpeg: %s", " ".join(ffmpeg_cmd))
        self._ffmpeg_process = await asyncio.create_subprocess_exec(
            *ffmpeg_cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )

        # Set up stream data callback to write to the pipe
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

            # Update codec if detected
            if data.codec == VideoCodec.H265 and video_codec != "hevc":
                _LOGGER.debug("Detected H.265 codec")

            # Store last frame as snapshot
            self._last_image = data.data

        session.set_stream_callback(on_stream_data)
        session.set_disconnect_callback(self._on_p2p_disconnect)

        # Start the livestream
        started = await session.start_livestream(channel=channel)
        if not started:
            _LOGGER.warning("Failed to start P2P stream for %s", self._device_sn)
            await self._cleanup_ffmpeg()
            return

        _LOGGER.info("P2P stream started for %s via ffmpeg", self._device_sn)
        self.async_write_ha_state()

    async def _stop_p2p_stream(self) -> None:
        """Stop P2P stream and clean up ffmpeg."""
        if self._p2p_session:
            device = self._device
            channel = device.device_channel if device else 0
            try:
                await self._p2p_session.stop_livestream(channel=channel)
            except Exception:
                pass
            await self._p2p_session.disconnect()
            self._p2p_session = None

        await self._cleanup_ffmpeg()

    async def _cleanup_ffmpeg(self) -> None:
        """Clean up ffmpeg process and named pipe."""
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

    # ----- Helpers -----

    async def _ensure_p2p_session(self) -> P2PSession | None:
        """Get or create a P2P session to the camera's station."""
        if self._p2p_session and self._p2p_session.connected:
            return self._p2p_session

        device = self._device
        if not device:
            return None

        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            _LOGGER.warning("Station %s not found for camera %s", device.station_sn, device.device_sn)
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

        connected = await self._p2p_session.connect()
        if not connected:
            _LOGGER.warning("Failed to establish P2P for %s", device.device_sn)
            self._p2p_session = None
            return None

        return self._p2p_session

    @staticmethod
    async def _find_free_port() -> int:
        """Find a free TCP port."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def _on_p2p_disconnect(self) -> None:
        """Handle P2P disconnection."""
        _LOGGER.debug("P2P disconnected for %s", self._device_sn)
        self._p2p_session = None
        self.hass.async_create_task(self._cleanup_ffmpeg())
        self._stream_source = None
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        """Clean up on removal."""
        if self._p2p_session:
            await self._p2p_session.disconnect()
        await self._cleanup_ffmpeg()
