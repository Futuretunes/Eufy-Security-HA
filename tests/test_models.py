"""Tests for data models."""

from custom_components.eufy_security_advanced.lib.models import (
    CloudPersistentData,
    DeviceData,
    PushMessage,
    StationData,
    StreamData,
)
from custom_components.eufy_security_advanced.lib.types import (
    DeviceType,
    GuardMode,
    VideoCodec,
)


class TestDeviceData:
    def test_is_camera(self):
        d = DeviceData(device_sn="T1", device_name="Cam", device_type=DeviceType.CAMERA2, station_sn="S1")
        assert d.is_camera is True
        assert d.is_lock is False
        assert d.is_sensor is False

    def test_is_doorbell(self):
        d = DeviceData(device_sn="T1", device_name="Bell", device_type=DeviceType.BATTERY_DOORBELL, station_sn="S1")
        assert d.is_doorbell is True
        assert d.is_camera is True  # Doorbells are also cameras

    def test_is_lock(self):
        d = DeviceData(device_sn="T1", device_name="Lock", device_type=DeviceType.LOCK_WIFI, station_sn="S1")
        assert d.is_lock is True
        assert d.is_camera is False

    def test_is_sensor(self):
        d = DeviceData(device_sn="T1", device_name="Sensor", device_type=DeviceType.SENSOR, station_sn="S1")
        assert d.is_sensor is True

    def test_has_battery(self):
        d = DeviceData(device_sn="T1", device_name="Cam", device_type=DeviceType.CAMERA2C, station_sn="S1")
        assert d.has_battery is True

    def test_has_no_battery(self):
        d = DeviceData(device_sn="T1", device_name="Cam", device_type=DeviceType.INDOOR_CAMERA, station_sn="S1")
        assert d.has_battery is False

    def test_params(self):
        d = DeviceData(device_sn="T1", device_name="Cam", device_type=DeviceType.CAMERA2, station_sn="S1")
        d.update_param(2005, "3")
        assert d.get_param(2005) == "3"
        assert d.get_param(9999, "default") == "default"

    def test_model_from_sn(self):
        d = DeviceData(device_sn="T8010ABC", device_name="Cam", device_type=DeviceType.CAMERA2, station_sn="S1")
        assert d.model == "T8010"


class TestStationData:
    def test_basic(self):
        s = StationData(
            station_sn="T8010XXXXX",
            station_name="Home Base",
            device_type=DeviceType.STATION,
            p2p_did="ABCD1234-123456-EFGH5678",
            guard_mode=GuardMode.HOME,
        )
        assert s.guard_mode == GuardMode.HOME
        assert s.model == "T8010"


class TestPushMessage:
    def test_basic(self):
        msg = PushMessage(
            device_sn="T1",
            station_sn="S1",
            event_type=3101,
            title="Motion Detected",
        )
        assert msg.event_type == 3101
        assert msg.sensor_open is None


class TestStreamData:
    def test_video(self):
        sd = StreamData(
            is_video=True,
            codec=VideoCodec.H264,
            data=b"\x00\x00\x00\x01\x67",
            is_keyframe=True,
            width=1920,
            height=1080,
            fps=30,
        )
        assert sd.is_video is True
        assert sd.width == 1920
