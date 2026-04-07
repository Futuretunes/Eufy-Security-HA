"""MCS (Mobile Connection Server) persistent connection for receiving FCM push messages.

Connects to mtalk.google.com:5228 via TLS and uses the protobuf-based MCS
protocol (same as Chrome/Android) to receive real-time push notifications.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import ssl
import struct
from typing import Any, Callable

from ...const import FCM_MCS_HOST, FCM_MCS_PORT, FCM_MCS_VERSION

_LOGGER = logging.getLogger(__name__)

# MCS message tags
TAG_HEARTBEAT_PING = 0
TAG_HEARTBEAT_ACK = 1
TAG_LOGIN_REQUEST = 2
TAG_LOGIN_RESPONSE = 3
TAG_CLOSE = 4
TAG_IQ_STANZA = 7
TAG_DATA_MESSAGE = 8
TAG_STREAM_ERROR = 10

# Heartbeat interval (5 minutes)
HEARTBEAT_INTERVAL = 300

# Reconnection backoff
INITIAL_BACKOFF = 5
MAX_BACKOFF = 600


class MCSProtobufBuilder:
    """Minimal protobuf encoder for MCS messages (no compiled protos needed)."""

    @staticmethod
    def _varint(value: int) -> bytes:
        result = bytearray()
        while value > 0x7F:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value & 0x7F)
        return bytes(result)

    @staticmethod
    def _field_varint(field_num: int, value: int) -> bytes:
        tag = MCSProtobufBuilder._varint((field_num << 3) | 0)
        return tag + MCSProtobufBuilder._varint(value)

    @staticmethod
    def _field_string(field_num: int, value: str | bytes) -> bytes:
        if isinstance(value, str):
            value = value.encode()
        tag = MCSProtobufBuilder._varint((field_num << 3) | 2)
        return tag + MCSProtobufBuilder._varint(len(value)) + value

    @staticmethod
    def _field_bool(field_num: int, value: bool) -> bytes:
        return MCSProtobufBuilder._field_varint(field_num, 1 if value else 0)

    @staticmethod
    def _field_submessage(field_num: int, data: bytes) -> bytes:
        tag = MCSProtobufBuilder._varint((field_num << 3) | 2)
        return tag + MCSProtobufBuilder._varint(len(data)) + data

    @classmethod
    def build_login_request(
        cls,
        android_id: int,
        security_token: int,
        received_persistent_ids: list[str] | None = None,
    ) -> bytes:
        """Build an MCS LoginRequest protobuf."""
        # LoginRequest fields:
        # 1: id (string)
        # 2: domain (string)
        # 3: user (string)
        # 4: resource (string)
        # 5: auth_token (string)
        # 6: device_id (string)
        # 9: setting (repeated Setting submessage)
        # 11: auth_service (varint, 2=ANDROID_ID)
        # 12: adaptive_heartbeat (bool)
        # 14: use_rmq2 (bool)
        # 17: network_type (varint)
        # 19: received_persistent_id (repeated string)

        setting = cls._field_string(1, "new_vc") + cls._field_string(2, "1")

        msg = (
            cls._field_string(1, "chrome-63.0.3234.0")
            + cls._field_string(2, "mcs.android.com")
            + cls._field_string(3, str(android_id))
            + cls._field_string(4, str(android_id))
            + cls._field_string(5, str(security_token))
            + cls._field_string(6, f"android-{android_id:x}")
            + cls._field_submessage(9, setting)
            + cls._field_varint(11, 2)  # ANDROID_ID auth
            + cls._field_bool(12, False)  # adaptive_heartbeat
            + cls._field_bool(14, True)  # use_rmq2
            + cls._field_varint(17, 1)  # network_type
        )

        for pid in (received_persistent_ids or []):
            msg += cls._field_string(19, pid)

        return msg

    @classmethod
    def build_heartbeat_ping(cls) -> bytes:
        """Build an MCS HeartbeatPing protobuf (empty message is valid)."""
        return b""

    @classmethod
    def build_heartbeat_ack(cls) -> bytes:
        """Build an MCS HeartbeatAck protobuf."""
        return b""


class MCSProtobufParser:
    """Minimal protobuf decoder for MCS response messages."""

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
    def parse_fields(cls, data: bytes) -> dict[int, list[Any]]:
        """Parse protobuf fields into {field_num: [values]}."""
        fields: dict[int, list[Any]] = {}
        pos = 0
        while pos < len(data):
            tag, pos = cls._read_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 0:  # varint
                value, pos = cls._read_varint(data, pos)
            elif wire_type == 2:  # length-delimited
                length, pos = cls._read_varint(data, pos)
                value = data[pos : pos + length]
                pos += length
            elif wire_type == 5:  # 32-bit
                value = data[pos : pos + 4]
                pos += 4
            elif wire_type == 1:  # 64-bit
                value = data[pos : pos + 8]
                pos += 8
            else:
                break

            fields.setdefault(field_num, []).append(value)

        return fields

    @classmethod
    def parse_data_message(cls, data: bytes) -> dict[str, Any]:
        """Parse a DataMessageStanza protobuf.

        Fields:
        1: id (string)
        2: from (string)
        3: to (string)
        4: category (string)
        7: app_data (repeated KeyValue submessage)
        8: persistent_id (string)
        9: ttl (varint)
        10: sent (varint)
        """
        fields = cls.parse_fields(data)

        result: dict[str, Any] = {}
        if 1 in fields:
            result["id"] = fields[1][0].decode("utf-8", errors="replace") if isinstance(fields[1][0], bytes) else str(fields[1][0])
        if 2 in fields:
            result["from"] = fields[2][0].decode("utf-8", errors="replace") if isinstance(fields[2][0], bytes) else str(fields[2][0])
        if 3 in fields:
            result["to"] = fields[3][0].decode("utf-8", errors="replace") if isinstance(fields[3][0], bytes) else str(fields[3][0])
        if 4 in fields:
            result["category"] = fields[4][0].decode("utf-8", errors="replace") if isinstance(fields[4][0], bytes) else str(fields[4][0])
        if 8 in fields:
            result["persistent_id"] = fields[8][0].decode("utf-8", errors="replace") if isinstance(fields[8][0], bytes) else str(fields[8][0])
        if 9 in fields:
            result["ttl"] = fields[9][0]
        if 10 in fields:
            result["sent"] = fields[10][0]

        # Parse app_data key-value pairs
        app_data: dict[str, str] = {}
        for kv_bytes in fields.get(7, []):
            if isinstance(kv_bytes, bytes):
                kv_fields = cls.parse_fields(kv_bytes)
                key = kv_fields.get(1, [b""])[0]
                value = kv_fields.get(2, [b""])[0]
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="replace")
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                app_data[key] = value
        result["app_data"] = app_data

        return result


class MCSClient:
    """Persistent MCS connection for receiving FCM push messages."""

    def __init__(
        self,
        android_id: int,
        security_token: int,
        on_message: Callable[[dict[str, Any]], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
    ) -> None:
        self._android_id = android_id
        self._security_token = security_token
        self._on_message = on_message
        self._on_disconnect = on_disconnect

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._connected = False
        self._received_persistent_ids: list[str] = []

        self._recv_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._reconnect_backoff = INITIAL_BACKOFF

    @property
    def connected(self) -> bool:
        return self._connected

    async def connect(self) -> None:
        """Connect to MCS and authenticate."""
        # Create SSL context in executor to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        ssl_context = await loop.run_in_executor(None, ssl.create_default_context)

        self._reader, self._writer = await asyncio.open_connection(
            FCM_MCS_HOST, FCM_MCS_PORT, ssl=ssl_context
        )

        # Send MCS version + login request
        login = MCSProtobufBuilder.build_login_request(
            self._android_id,
            self._security_token,
            self._received_persistent_ids,
        )

        # Wire format: [version(1)] [tag(1)] [varint length] [proto bytes]
        header = bytes([FCM_MCS_VERSION, TAG_LOGIN_REQUEST])
        self._writer.write(header + self._encode_delimited(login))
        await self._writer.drain()

        # Read version + login response
        version = await self._reader.readexactly(1)
        if version[0] != FCM_MCS_VERSION:
            _LOGGER.warning("Unexpected MCS version: %d", version[0])

        tag, data = await self._read_message()
        if tag != TAG_LOGIN_RESPONSE:
            raise RuntimeError(f"Expected LoginResponse, got tag {tag}")

        self._connected = True
        self._reconnect_backoff = INITIAL_BACKOFF
        _LOGGER.info("MCS connected to %s:%d", FCM_MCS_HOST, FCM_MCS_PORT)

        # Start receive and heartbeat loops
        self._recv_task = asyncio.create_task(self._receive_loop())
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def disconnect(self) -> None:
        """Close the MCS connection."""
        self._connected = False
        for task in (self._recv_task, self._heartbeat_task):
            if task and not task.done():
                task.cancel()
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass

    async def run_forever(self) -> None:
        """Connect and automatically reconnect on failure."""
        while True:
            try:
                await self.connect()
                # Wait for receive task to complete (on disconnect/error)
                if self._recv_task:
                    await self._recv_task
            except asyncio.CancelledError:
                await self.disconnect()
                return
            except Exception:
                _LOGGER.exception("MCS connection error")

            self._connected = False
            if self._on_disconnect:
                self._on_disconnect()

            _LOGGER.info("MCS reconnecting in %ds", self._reconnect_backoff)
            await asyncio.sleep(self._reconnect_backoff)
            if self._reconnect_backoff < 60:
                self._reconnect_backoff += 10
            elif self._reconnect_backoff < MAX_BACKOFF:
                self._reconnect_backoff += 60

    @staticmethod
    def _encode_delimited(data: bytes) -> bytes:
        """Encode a protobuf message with a varint length prefix."""
        length = len(data)
        result = bytearray()
        while length > 0x7F:
            result.append((length & 0x7F) | 0x80)
            length >>= 7
        result.append(length & 0x7F)
        return bytes(result) + data

    async def _read_varint(self) -> int:
        """Read a varint from the stream."""
        result = 0
        shift = 0
        while True:
            byte_data = await self._reader.readexactly(1)
            b = byte_data[0]
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result

    async def _read_message(self) -> tuple[int, bytes]:
        """Read a single MCS message (tag + varint size + proto bytes)."""
        tag_byte = await self._reader.readexactly(1)
        tag = tag_byte[0]
        size = await self._read_varint()
        if size > 0:
            data = await self._reader.readexactly(size)
        else:
            data = b""
        return tag, data

    async def _receive_loop(self) -> None:
        """Continuously read MCS messages."""
        try:
            while self._connected:
                tag, data = await self._read_message()

                if tag == TAG_HEARTBEAT_PING:
                    await self._send_message(TAG_HEARTBEAT_ACK, MCSProtobufBuilder.build_heartbeat_ack())

                elif tag == TAG_DATA_MESSAGE:
                    self._handle_data_message(data)

                elif tag == TAG_CLOSE:
                    _LOGGER.info("MCS server sent close")
                    break

                elif tag == TAG_IQ_STANZA:
                    pass  # Ignored

                elif tag == TAG_STREAM_ERROR:
                    _LOGGER.warning("MCS stream error")
                    break

        except asyncio.IncompleteReadError:
            _LOGGER.debug("MCS connection closed by server")
        except asyncio.CancelledError:
            pass
        except Exception:
            _LOGGER.exception("MCS receive error")

    async def _send_message(self, tag: int, data: bytes) -> None:
        """Send an MCS message."""
        if not self._writer:
            return
        self._writer.write(bytes([tag]) + self._encode_delimited(data))
        await self._writer.drain()

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat pings."""
        try:
            while self._connected:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if self._connected:
                    await self._send_message(
                        TAG_HEARTBEAT_PING,
                        MCSProtobufBuilder.build_heartbeat_ping(),
                    )
        except asyncio.CancelledError:
            pass

    def _handle_data_message(self, data: bytes) -> None:
        """Parse and dispatch a DataMessageStanza."""
        parsed = MCSProtobufParser.parse_data_message(data)

        persistent_id = parsed.get("persistent_id", "")
        if persistent_id:
            self._received_persistent_ids.append(persistent_id)
            # Keep last 100
            if len(self._received_persistent_ids) > 100:
                self._received_persistent_ids = self._received_persistent_ids[-100:]

        if self._on_message:
            self._on_message(parsed)
