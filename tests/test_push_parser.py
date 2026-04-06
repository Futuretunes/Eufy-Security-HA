"""Tests for push notification message parsing."""

import base64
import json

from custom_components.eufy_security_advanced.lib.push.parser import (
    parse_push_message,
    _parse_eufy_message,
)


class TestParsePushMessage:
    def _make_raw(self, eufy_msg: dict) -> dict:
        """Build a raw FCM message with a base64-encoded Eufy payload."""
        payload_bytes = json.dumps(eufy_msg).encode("utf-8") + b"\x00"
        return {"app_data": {"payload": base64.b64encode(payload_bytes).decode()}}

    def test_motion_detection(self):
        raw = self._make_raw({
            "device_sn": "T8112N1234",
            "station_sn": "T8010S1234",
            "title": "Motion Detected",
            "content": "Camera detected motion",
            "event_time": "1704067200",
            "type": "9",
            "payload": {
                "a": 3101,
                "c": 0,
                "p": "/media/image.jpg",
                "pic_url": "https://example.com/thumb.jpg",
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.device_sn == "T8112N1234"
        assert msg.station_sn == "T8010S1234"
        assert msg.event_type == 3101
        assert msg.pic_url == "https://example.com/thumb.jpg"
        assert msg.file_path == "/media/image.jpg"

    def test_person_detection(self):
        raw = self._make_raw({
            "device_sn": "T8112N1234",
            "station_sn": "T8010S1234",
            "type": "7",
            "payload": {
                "a": 3102,
                "f": "John",
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.event_type == 3102
        assert msg.person_name == "John"

    def test_door_sensor(self):
        raw = self._make_raw({
            "device_sn": "T8900S1234",
            "station_sn": "T8010S1234",
            "type": "2",
            "payload": {
                "a": 3,
                "e": "1",
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.event_type == 3
        assert msg.sensor_open is True

    def test_door_sensor_closed(self):
        raw = self._make_raw({
            "device_sn": "T8900S1234",
            "station_sn": "T8010S1234",
            "type": "2",
            "payload": {
                "a": 3,
                "e": "0",
            },
        })
        msg = parse_push_message(raw)
        assert msg.sensor_open is False

    def test_guard_mode_change(self):
        raw = self._make_raw({
            "device_sn": "",
            "station_sn": "T8010S1234",
            "type": "0",
            "payload": {
                "a": 9,
                "arming": 0,
                "mode": 0,
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.guard_mode == 0

    def test_lock_event(self):
        raw = self._make_raw({
            "device_sn": "T8530L1234",
            "station_sn": "T8010S1234",
            "type": "51",
            "payload": {
                "event_type": 261,
                "nick_name": "Alice",
                "user_id": "user123",
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.event_type == 261
        assert msg.nick_name == "Alice"
        assert msg.user_id == "user123"

    def test_wired_doorbell_uses_doorbell_field(self):
        raw = self._make_raw({
            "device_sn": "T8200D1234",
            "station_sn": "T8010S1234",
            "type": "5",
            "doorbell": json.dumps({
                "event_type": 3103,
                "channel": 0,
                "pic_url": "https://example.com/doorbell.jpg",
            }),
            "payload": {},
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.event_type == 3103
        assert msg.pic_url == "https://example.com/doorbell.jpg"

    def test_empty_payload_returns_none(self):
        assert parse_push_message({"app_data": {}}) is None
        assert parse_push_message({"app_data": {"payload": ""}}) is None

    def test_invalid_base64_returns_none(self):
        assert parse_push_message({"app_data": {"payload": "not_valid!!"}}) is None

    def test_long_field_names(self):
        """Test that long-form field names work (not just short aliases)."""
        raw = self._make_raw({
            "device_sn": "T8112N1234",
            "station_sn": "T8010S1234",
            "type": "9",
            "payload": {
                "event_type": 3101,
                "channel": 0,
                "file_path": "/media/event.jpg",
                "pic_url": "https://example.com/pic.jpg",
            },
        })
        msg = parse_push_message(raw)
        assert msg is not None
        assert msg.event_type == 3101
        assert msg.file_path == "/media/event.jpg"
