"""Eufy Security MQTT client for smart lock communication."""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Any, Callable

from ...const import MQTT_BROKERS, MQTT_KEEPALIVE, MQTT_PORT
from ..types import LockPushEvent

_LOGGER = logging.getLogger(__name__)


class MQTTProtobufParser:
    """Minimal protobuf parser for DeviceSmartLockMessage."""

    @staticmethod
    def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
        result = 0
        shift = 0
        while pos < len(data):
            b = data[pos]
            result |= (b & 0x7F) << shift
            pos += 1
            if not (b & 0x80):
                break
            shift += 7
        return result, pos

    @classmethod
    def parse_lock_message(cls, data: bytes) -> dict[str, Any] | None:
        """Parse a DeviceSmartLockMessage protobuf.

        Message structure:
        1: event_type (uint32)
        2: user_id (string)
        3: data (DeviceSmartLockNotify submessage)
            1: timestamp (uint64)
            2: uuid (string)
            3: data (DeviceSmartLockNotifyData submessage)
                1: station_sn (string)
                2: device_sn (string)
                3: event_type (uint32)
                4: event_time (uint64)
                5: short_user_id (string)
                7: nick_name (string)
                8: user_id (string)
                10: device_name (string)
                12: lock_state (string)
        """
        try:
            fields = cls._parse_fields(data)
            result: dict[str, Any] = {}

            if 1 in fields:
                result["event_type"] = fields[1]
            if 2 in fields:
                result["user_id"] = cls._to_str(fields[2])

            if 3 in fields and isinstance(fields[3], bytes):
                notify = cls._parse_fields(fields[3])
                if 3 in notify and isinstance(notify[3], bytes):
                    notify_data = cls._parse_fields(notify[3])
                    result["station_sn"] = cls._to_str(notify_data.get(1, b""))
                    result["device_sn"] = cls._to_str(notify_data.get(2, b""))
                    result["data_event_type"] = notify_data.get(3, 0)
                    result["event_time"] = notify_data.get(4, 0)
                    result["short_user_id"] = cls._to_str(notify_data.get(5, b""))
                    result["nick_name"] = cls._to_str(notify_data.get(7, b""))
                    result["data_user_id"] = cls._to_str(notify_data.get(8, b""))
                    result["device_name"] = cls._to_str(notify_data.get(10, b""))
                    result["lock_state"] = cls._to_str(notify_data.get(12, b""))

            return result if result else None
        except Exception:
            _LOGGER.debug("Failed to parse lock protobuf", exc_info=True)
            return None

    @classmethod
    def _parse_fields(cls, data: bytes) -> dict[int, Any]:
        """Parse protobuf fields — returns last value for each field number."""
        fields: dict[int, Any] = {}
        pos = 0
        while pos < len(data):
            tag, pos = cls._read_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:
                value, pos = cls._read_varint(data, pos)
                fields[field_num] = value
            elif wire_type == 2:
                length, pos = cls._read_varint(data, pos)
                fields[field_num] = data[pos : pos + length]
                pos += length
            elif wire_type == 5:
                pos += 4
            elif wire_type == 1:
                pos += 8
            else:
                break
        return fields

    @staticmethod
    def _to_str(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)


class EufyMQTTClient:
    """Async MQTT client for Eufy smart lock events."""

    def __init__(
        self,
        user_id: str,
        email: str,
        api_base: str,
        device_sns: list[str] | None = None,
        on_lock_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._user_id = user_id
        self._email = email
        self._api_base = api_base
        self._device_sns = device_sns or []
        self._on_lock_event = on_lock_event
        self._client = None
        self._connected = False
        self._task: asyncio.Task | None = None

    @property
    def broker_host(self) -> str:
        return MQTT_BROKERS.get(self._api_base, "security-mqtt.eufylife.com")

    @property
    def connected(self) -> bool:
        return self._connected

    def add_device(self, device_sn: str) -> None:
        if device_sn not in self._device_sns:
            self._device_sns.append(device_sn)

    async def connect(self) -> None:
        """Connect to the Eufy MQTT broker."""
        try:
            import aiomqtt
        except ImportError:
            _LOGGER.error("aiomqtt not installed, MQTT lock support unavailable")
            return

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE  # Eufy's certs are sometimes expired

        username = f"eufy_{self._user_id}"
        client_id = f"android_EufySecurity_{self._user_id}"

        self._task = asyncio.create_task(
            self._run(aiomqtt, ssl_context, username, client_id)
        )

    async def _run(
        self, aiomqtt: Any, ssl_context: ssl.SSLContext, username: str, client_id: str
    ) -> None:
        """Main MQTT loop with auto-reconnect."""
        while True:
            try:
                async with aiomqtt.Client(
                    hostname=self.broker_host,
                    port=MQTT_PORT,
                    username=username,
                    password=self._email,
                    identifier=client_id,
                    tls_context=ssl_context,
                    keepalive=MQTT_KEEPALIVE,
                    clean_start=True,
                ) as client:
                    self._connected = True
                    _LOGGER.info("MQTT connected to %s", self.broker_host)

                    # Subscribe to notice topic
                    await client.subscribe(f"/phone/{self._user_id}/notice", qos=1)

                    # Subscribe to each lock device
                    for sn in self._device_sns:
                        topic = f"/phone/smart_lock/{sn}/push_message"
                        await client.subscribe(topic, qos=1)
                        _LOGGER.debug("MQTT subscribed to %s", topic)

                    async for message in client.messages:
                        self._handle_message(str(message.topic), message.payload)

            except asyncio.CancelledError:
                self._connected = False
                return
            except Exception:
                _LOGGER.exception("MQTT connection error")
                self._connected = False
                await asyncio.sleep(30)

    def _handle_message(self, topic: str, payload: bytes) -> None:
        """Handle an incoming MQTT message."""
        if "smart_lock" in topic:
            parsed = MQTTProtobufParser.parse_lock_message(payload)
            if parsed and self._on_lock_event:
                self._on_lock_event(parsed)
        else:
            _LOGGER.debug("MQTT message on %s: %d bytes", topic, len(payload))

    async def disconnect(self) -> None:
        """Disconnect the MQTT client."""
        self._connected = False
        if self._task and not self._task.done():
            self._task.cancel()
