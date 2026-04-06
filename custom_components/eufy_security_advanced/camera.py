"""Camera platform for Eufy Security devices."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import EufySecurityCoordinator
from .entity import EufySecurityEntity
from .lib.models import DeviceData, StreamData
from .lib.p2p.session import P2PSession
from .lib.types import DOORBELL_TYPES, VideoCodec

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
    """Camera entity with P2P livestream support."""

    _attr_name = "Camera"
    _attr_supported_features = CameraEntityFeature.STREAM

    def __init__(self, coordinator: EufySecurityCoordinator, device: DeviceData) -> None:
        EufySecurityEntity.__init__(self, coordinator, device, "camera")
        Camera.__init__(self)
        self._p2p_session: P2PSession | None = None
        self._last_image: bytes | None = None
        self._stream_buffer: asyncio.Queue[StreamData] = asyncio.Queue(maxsize=100)

    @property
    def is_streaming(self) -> bool:
        return self._p2p_session is not None and self._p2p_session.is_streaming

    @property
    def motion_detection_enabled(self) -> bool:
        device = self._device
        if device:
            return device.get_param(2027, "1") != "0"
        return True

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

    async def async_turn_on(self) -> None:
        """Start the livestream via P2P."""
        device = self._device
        if not device:
            return

        station = self.coordinator.stations.get(device.station_sn)
        if not station:
            _LOGGER.warning("Station %s not found for camera %s", device.station_sn, device.device_sn)
            return

        if self._p2p_session and self._p2p_session.connected:
            return

        # Get DSK keys
        dsk_keys = await self.coordinator.api.get_dsk_keys()
        dsk_data = dsk_keys.get(station.station_sn, {})
        dsk_key = dsk_data.get("dsk_key", "")

        cloud_ips = station.p2p_cloud_ips or []

        self._p2p_session = P2PSession(
            station_sn=station.station_sn,
            p2p_did=station.p2p_did,
            dsk_key=dsk_key,
            cloud_ips=cloud_ips,
            admin_user_id=self.coordinator.api.persistent_data.user_id,
            get_cipher_callback=self.coordinator.api.get_ciphers,
        )
        self._p2p_session.set_stream_callback(self._on_stream_data)
        self._p2p_session.set_disconnect_callback(self._on_p2p_disconnect)

        connected = await self._p2p_session.connect()
        if connected:
            await self._p2p_session.start_livestream(channel=device.device_channel)
        else:
            _LOGGER.warning("Failed to establish P2P connection for %s", device.device_sn)

    async def async_turn_off(self) -> None:
        """Stop the livestream."""
        if self._p2p_session:
            device = self._device
            channel = device.device_channel if device else 0
            await self._p2p_session.stop_livestream(channel=channel)
            await self._p2p_session.disconnect()
            self._p2p_session = None

    def _on_stream_data(self, data: StreamData) -> None:
        """Receive video/audio data from P2P session."""
        try:
            self._stream_buffer.put_nowait(data)
        except asyncio.QueueFull:
            pass  # Drop frame if consumer is too slow

        if data.is_video and data.data:
            # Store last frame as snapshot
            self._last_image = data.data

    def _on_p2p_disconnect(self) -> None:
        """Handle P2P disconnection."""
        _LOGGER.debug("P2P disconnected for %s", self._device_sn)
        self._p2p_session = None
        self.async_write_ha_state()

    async def async_will_remove_from_hass(self) -> None:
        """Clean up P2P session on removal."""
        if self._p2p_session:
            await self._p2p_session.disconnect()
