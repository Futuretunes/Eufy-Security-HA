"""Data models for Eufy Security devices and stations."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .types import DeviceType, GuardMode, BATTERY_TYPES, CAMERA_TYPES, DOORBELL_TYPES, LOCK_TYPES, SENSOR_TYPES

_LOGGER = logging.getLogger(__name__)


@dataclass
class StationData:
    """Represents a Eufy HomeBase / station."""

    station_sn: str
    station_name: str
    device_type: DeviceType
    p2p_did: str
    member: dict[str, Any] = field(default_factory=dict)
    main_sw_version: str = ""
    main_hw_version: str = ""
    ip_addr: str = ""
    mac_addr: str = ""
    guard_mode: GuardMode = GuardMode.UNKNOWN
    current_mode: GuardMode = GuardMode.UNKNOWN
    devices: list[str] = field(default_factory=list)

    # P2P connection data (decoded from cloud)
    p2p_cloud_ips: list[tuple[str, int]] = field(default_factory=list)
    app_conn: str = ""
    dsk_keys: list[dict[str, Any]] = field(default_factory=list)

    # Raw cloud data
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def model(self) -> str:
        return self.raw.get("model", self.station_sn[:5] if self.station_sn else "Unknown")


@dataclass
class DeviceData:
    """Represents a Eufy device (camera, sensor, lock, doorbell, etc.)."""

    device_sn: str
    device_name: str
    device_type: DeviceType
    station_sn: str
    device_model: str = ""
    device_channel: int = 0
    main_sw_version: str = ""
    main_hw_version: str = ""
    ip_addr: str = ""
    mac_addr: str = ""

    # State
    battery_level: int = -1
    wifi_rssi: int = 0
    is_online: bool = False

    # Camera-specific
    is_streaming: bool = False
    motion_detected: bool = False
    person_detected: bool = False
    pet_detected: bool = False
    vehicle_detected: bool = False
    crying_detected: bool = False
    sound_detected: bool = False
    last_event_pic_url: str = ""
    last_event_time: int = 0

    # Sensor-specific
    sensor_open: bool = False

    # Lock-specific
    is_locked: bool = True
    lock_event_type: int = 0
    lock_event_user: str = ""

    # Parameters (from cloud)
    params: dict[int, Any] = field(default_factory=dict)

    # Raw cloud data
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_camera(self) -> bool:
        return self.device_type in CAMERA_TYPES or self.device_type in DOORBELL_TYPES

    @property
    def is_doorbell(self) -> bool:
        return self.device_type in DOORBELL_TYPES

    @property
    def is_lock(self) -> bool:
        return self.device_type in LOCK_TYPES

    @property
    def is_sensor(self) -> bool:
        return self.device_type in SENSOR_TYPES

    @property
    def has_battery(self) -> bool:
        return self.device_type in BATTERY_TYPES

    @property
    def model(self) -> str:
        return self.device_model or (self.device_sn[:5] if self.device_sn else "Unknown")

    def update_param(self, param_type: int, value: Any) -> None:
        """Update a device parameter."""
        self.params[param_type] = value

    def get_param(self, param_type: int, default: Any = None) -> Any:
        """Get a device parameter value."""
        return self.params.get(param_type, default)


@dataclass
class PushMessage:
    """Parsed push notification from FCM."""

    device_sn: str
    station_sn: str
    event_type: int
    event_time: int = 0
    title: str = ""
    content: str = ""
    channel: int = 0
    cipher: int = 0
    pic_url: str = ""
    file_path: str = ""
    person_name: str = ""
    sensor_open: bool | None = None
    nick_name: str = ""
    user_id: str = ""
    guard_mode: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamData:
    """Container for a video/audio stream segment."""

    is_video: bool
    codec: int  # VideoCodec or AudioCodec value
    data: bytes = b""
    is_keyframe: bool = False
    width: int = 0
    height: int = 0
    fps: int = 0
    sequence: int = 0
    timestamp: int = 0


@dataclass
class P2PSessionData:
    """Persistent P2P session state."""

    user_id: str = ""
    station_sn: str = ""
    p2p_did: str = ""
    dsk_key: str = ""
    encryption_level: int = 0
    p2p_key: bytes = b""
    connect_address: tuple[str, int] | None = None
    local_address: tuple[str, int] | None = None


@dataclass
class CloudPersistentData:
    """Persistent cloud API state for session recovery."""

    user_id: str = ""
    email: str = ""
    nick_name: str = ""
    client_private_key: str = ""
    server_public_key: str = ""
    auth_token: str = ""
    token_expires_at: int = 0
    api_base: str = ""
    domain: str = ""
