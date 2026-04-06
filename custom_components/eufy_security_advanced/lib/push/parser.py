"""Push notification message parser — converts raw FCM payloads to PushMessage objects."""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

from ..models import PushMessage
from ..types import (
    CusPushEvent,
    DeviceType,
    DoorbellPushEvent,
    IndoorPushEvent,
    LockPushEvent,
    SmartSafeEvent,
    CAMERA_TYPES,
    DOORBELL_TYPES,
    LOCK_TYPES,
    SENSOR_TYPES,
)

_LOGGER = logging.getLogger(__name__)


def parse_push_message(raw: dict[str, Any]) -> PushMessage | None:
    """Parse a raw FCM DataMessageStanza into a PushMessage.

    The raw dict has:
    - app_data: dict with key "payload" containing base64-encoded JSON
    """
    app_data = raw.get("app_data", {})
    payload_b64 = app_data.get("payload", "")
    if not payload_b64:
        return None

    try:
        payload_bytes = base64.b64decode(payload_b64)
        # Null-terminated
        payload_str = payload_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
        eufy_msg = json.loads(payload_str)
    except Exception:
        _LOGGER.debug("Failed to decode push payload: %s", payload_b64[:100])
        return None

    return _parse_eufy_message(eufy_msg)


def _parse_eufy_message(msg: dict[str, Any]) -> PushMessage | None:
    """Parse the Eufy push message envelope."""
    device_sn = msg.get("device_sn", "")
    station_sn = msg.get("station_sn", "")
    title = msg.get("title", "")
    content = msg.get("content", "")
    event_time_str = msg.get("event_time", "0")
    push_time_str = msg.get("push_time", "0")

    try:
        event_time = int(event_time_str)
    except (ValueError, TypeError):
        event_time = 0

    # Determine device type
    type_str = msg.get("type", "0")
    try:
        device_type = DeviceType(int(type_str))
    except (ValueError, TypeError):
        device_type = None

    # The actual push data is in msg["payload"] or msg["doorbell"]
    push_data = msg.get("payload", {})
    if isinstance(push_data, str):
        try:
            push_data = json.loads(push_data)
        except json.JSONDecodeError:
            push_data = {}

    # Wired doorbells use a "doorbell" field
    doorbell_data = msg.get("doorbell", "")
    if doorbell_data and isinstance(doorbell_data, str):
        try:
            doorbell_data = json.loads(doorbell_data)
        except json.JSONDecodeError:
            doorbell_data = {}
    if isinstance(doorbell_data, dict) and doorbell_data:
        push_data = doorbell_data

    if not push_data:
        return None

    # Extract common fields (Eufy uses both short and long field names)
    event_type = (
        push_data.get("a")
        or push_data.get("event_type")
        or 0
    )
    try:
        event_type = int(event_type)
    except (ValueError, TypeError):
        event_type = 0

    channel = push_data.get("c") or push_data.get("channel") or 0
    cipher = push_data.get("k") or push_data.get("cipher") or 0
    pic_url = push_data.get("pic_url", "")
    file_path = push_data.get("p") or push_data.get("file_path") or ""
    person_name = push_data.get("f") or push_data.get("person_name") or ""
    nick_name = push_data.get("nick_name", "")
    user_id = push_data.get("user_id", "")

    # Sensor open/close
    sensor_open_str = push_data.get("e")
    sensor_open = None
    if sensor_open_str is not None:
        sensor_open = str(sensor_open_str) == "1"

    # Guard mode from push
    guard_mode = push_data.get("arming") or push_data.get("mode")
    if guard_mode is not None:
        try:
            guard_mode = int(guard_mode)
        except (ValueError, TypeError):
            guard_mode = None

    # Fill device_sn from push_data if not in envelope
    if not device_sn:
        device_sn = push_data.get("device_sn", "")
    if not station_sn:
        station_sn = push_data.get("s") or push_data.get("station_sn") or ""

    return PushMessage(
        device_sn=device_sn,
        station_sn=station_sn,
        event_type=event_type,
        event_time=event_time,
        title=title,
        content=content,
        channel=channel,
        cipher=cipher,
        pic_url=pic_url,
        file_path=file_path,
        person_name=person_name,
        sensor_open=sensor_open,
        nick_name=nick_name,
        user_id=user_id,
        guard_mode=guard_mode,
        raw=push_data,
    )
