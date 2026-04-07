"""Eufy P2P UDP protocol — packet encoding and decoding."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ..types import P2PMessageType, P2PDataType, CommandType

# Magic word in data message headers
MAGIC_WORD = b"XZYH"


@dataclass
class UDPPacket:
    """A parsed UDP packet from the P2P protocol."""

    msg_type: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> UDPPacket | None:
        """Parse raw UDP data into a UDPPacket."""
        if len(data) < 4:
            return None
        msg_type = struct.unpack(">H", data[:2])[0]
        length = struct.unpack(">H", data[2:4])[0]
        payload = data[4 : 4 + length]
        return cls(msg_type=msg_type, payload=payload)

    def encode(self) -> bytes:
        """Encode the packet to wire format."""
        return (
            struct.pack(">H", self.msg_type)
            + struct.pack(">H", len(self.payload))
            + self.payload
        )


@dataclass
class DataMessage:
    """Parsed DATA (F1 D0) message payload.

    Wire format (both incoming and outgoing — NO bytes_to_read prefix):
      [data_type(2,BE)] [sequence(2,BE)] [data...]
    """

    data_type: int
    sequence: int
    data: bytes

    @classmethod
    def parse(cls, payload: bytes) -> DataMessage | None:
        """Parse a DATA message payload."""
        if len(payload) < 4:
            return None
        data_type = struct.unpack(">H", payload[0:2])[0]
        sequence = struct.unpack(">H", payload[2:4])[0]
        data = payload[4:]
        return cls(
            data_type=data_type,
            sequence=sequence,
            data=data,
        )


@dataclass
class XZYHHeader:
    """Parsed XZYH magic word header (16 bytes) in data payloads."""

    command_id: int
    bytes_to_read: int
    channel: int
    sign_code: int
    msg_type: int  # 0=request, 1=response

    @classmethod
    def parse(cls, data: bytes) -> XZYHHeader | None:
        """Parse a 16-byte XZYH header."""
        if len(data) < 16 or data[:4] != MAGIC_WORD:
            return None
        command_id = struct.unpack("<H", data[4:6])[0]
        bytes_to_read = struct.unpack("<I", data[6:10])[0]
        channel = data[12]
        sign_code = data[13]
        msg_type = data[14]
        return cls(
            command_id=command_id,
            bytes_to_read=bytes_to_read,
            channel=channel,
            sign_code=sign_code,
            msg_type=msg_type,
        )


@dataclass
class VideoFrameHeader:
    """Parsed video frame metadata after XZYH header."""

    data_length: int
    is_keyframe: bool
    stream_type: int  # 1=H264, 2=H265
    sequence: int
    fps: int
    width: int
    height: int
    timestamp: int

    @classmethod
    def parse(cls, data: bytes) -> VideoFrameHeader | None:
        """Parse video frame header (22+ bytes)."""
        if len(data) < 22:
            return None
        data_length = struct.unpack("<I", data[0:4])[0]
        is_keyframe = data[4] == 1
        stream_type = data[5]
        sequence = struct.unpack("<H", data[6:8])[0]
        fps = struct.unpack("<H", data[8:10])[0]
        width = struct.unpack("<H", data[10:12])[0]
        height = struct.unpack("<H", data[12:14])[0]
        timestamp = int.from_bytes(data[14:20], "little")
        return cls(
            data_length=data_length,
            is_keyframe=is_keyframe,
            stream_type=stream_type,
            sequence=sequence,
            fps=fps,
            width=width,
            height=height,
            timestamp=timestamp,
        )


@dataclass
class AudioFrameHeader:
    """Parsed audio frame metadata after XZYH header."""

    data_length: int
    audio_type: int  # 0=AAC, 1=AAC_LC, 7=AAC_ELD
    sequence: int
    timestamp: int

    @classmethod
    def parse(cls, data: bytes) -> AudioFrameHeader | None:
        """Parse audio frame header (16+ bytes)."""
        if len(data) < 16:
            return None
        data_length = struct.unpack("<I", data[0:4])[0]
        audio_type = data[5]
        sequence = struct.unpack("<H", data[6:8])[0]
        timestamp = int.from_bytes(data[8:14], "little")
        return cls(
            data_length=data_length,
            audio_type=audio_type,
            sequence=sequence,
            timestamp=timestamp,
        )


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

def build_udp_packet(msg_type: int, payload: bytes = b"") -> bytes:
    """Build a raw UDP packet."""
    return UDPPacket(msg_type=msg_type, payload=payload).encode()


def build_lookup_with_key(
    p2p_did_bytes: bytes,
    local_port: int,
    local_ip: str,
    dsk_key: str,
) -> bytes:
    """Build a LOOKUP_WITH_KEY (F1 26) payload."""
    # IP as 4 reversed bytes
    ip_parts = local_ip.split(".")
    ip_bytes = bytes(int(p) for p in reversed(ip_parts))

    payload = (
        p2p_did_bytes
        + b"\x00\x02"
        + struct.pack("<H", local_port)
        + ip_bytes
        + b"\x00" * 8
        + b"\x02\x04\x00\x00"
        + dsk_key.encode("ascii")
        + b"\x00" * 4
    )
    return build_udp_packet(P2PMessageType.LOOKUP_WITH_KEY, payload)


def build_lookup_with_key2(p2p_did_bytes: bytes, dsk_key: str) -> bytes:
    """Build a LOOKUP_WITH_KEY2 (F1 6A) payload."""
    payload = p2p_did_bytes + dsk_key.encode("ascii") + b"\x00" * 4
    return build_udp_packet(P2PMessageType.LOOKUP_WITH_KEY2, payload)


def build_local_lookup() -> bytes:
    """Build a LOCAL_LOOKUP (F1 30) broadcast packet."""
    return build_udp_packet(P2PMessageType.LOCAL_LOOKUP, b"\x00\x00")


def build_check_cam(p2p_did_bytes: bytes) -> bytes:
    """Build a CHECK_CAM (F1 41) packet."""
    return build_udp_packet(P2PMessageType.CHECK_CAM, p2p_did_bytes + b"\x00\x00\x00")


def build_check_cam2(data: bytes = b"") -> bytes:
    """Build a CHECK_CAM2 (F1 83) packet."""
    return build_udp_packet(P2PMessageType.CHECK_CAM2, data)


def build_ping(last_pong_data: bytes = b"") -> bytes:
    """Build a PING (F1 E0) packet."""
    return build_udp_packet(P2PMessageType.PING, last_pong_data)


def build_pong(data: bytes = b"") -> bytes:
    """Build a PONG (F1 E1) packet."""
    return build_udp_packet(P2PMessageType.PONG, data)


def build_end() -> bytes:
    """Build an END (F1 F0) packet."""
    return build_udp_packet(P2PMessageType.END)


def build_ack(data_type: int, sequence: int) -> bytes:
    """Build an ACK (F1 D1) for a received DATA packet."""
    payload = struct.pack(">H", data_type) + struct.pack(">H", 1) + struct.pack(">H", sequence)
    return build_udp_packet(P2PMessageType.ACK, payload)


def build_command_header(
    data_type: int,
    sequence: int,
    command_type: int,
) -> bytes:
    """Build the 10-byte command header for outgoing DATA messages.

    DEPRECATED: Only used by build_talkback_audio_frame. Regular commands
    should use build_data_message which constructs the full XZYH header.
    """
    return (
        struct.pack(">H", data_type)
        + struct.pack(">H", sequence)
        + MAGIC_WORD
        + struct.pack("<H", command_type)
    )


def _payload_header(data_len: int, channel: int = 0, sign_code: int = 0) -> bytes:
    """Build the standard 10-byte payload header prefix.

    All outgoing payload builders share this structure:
      [data_len(2,LE)] [00 00] [01 00] [channel] [sign_code] [00 00]
    """
    return (
        struct.pack("<H", data_len)
        + b"\x00\x00"
        + b"\x01\x00"
        + bytes([channel, sign_code])
        + b"\x00\x00"
    )


def build_command_payload_int(
    value: int,
    str_value: str = "",
    channel: int = 0,
    sign_code: int = 0,
) -> bytes:
    """Build a 'WithInt' command payload with 10-byte header.

    Structure: [header(10)] [value(4,LE)] [str_value(128, padded)]
    """
    str_bytes = str_value.encode("utf-8").ljust(128, b"\x00")[:128]
    data = struct.pack("<I", value) + str_bytes
    return _payload_header(len(data), channel, sign_code) + data


def build_command_payload_string(
    str_value: str,
    str_value_sub: str = "",
    channel: int = 0,
    sign_code: int = 0,
) -> bytes:
    """Build a 'WithString' command payload with 10-byte header.

    Structure: [header(10)] [0x00(5)] [str_value(128)] [str_value_sub(128)]
    """
    str_bytes = str_value.encode("utf-8").ljust(128, b"\x00")[:128]
    str_sub_bytes = str_value_sub.encode("utf-8").ljust(128, b"\x00")[:128]
    data = b"\x00" * 5 + str_bytes + str_sub_bytes
    return _payload_header(len(data), channel, sign_code) + data


def build_command_payload_json(
    json_str: str,
    channel: int = 255,
    sign_code: int = 0,
) -> bytes:
    """Build a 'WithStringPayload' command payload with 10-byte header."""
    json_bytes = json_str.encode("utf-8")
    return _payload_header(len(json_bytes), channel, sign_code) + json_bytes


def build_command_payload_int_string(
    value: int,
    value_sub: int,
    str_value: str = "",
    str_value_sub: str = "",
    channel: int = 0,
    sign_code: int = 0,
) -> bytes:
    """Build a 'WithIntString' command payload with 10-byte header.

    Structure: [header(10)] [valueSub(4,LE)] [value(4,LE)] [strValue(128)] [strValueSub(128)]
    """
    str_bytes = str_value.encode("utf-8").ljust(128, b"\x00")[:128]
    str_sub_bytes = str_value_sub.encode("utf-8").ljust(128, b"\x00")[:128]
    data = struct.pack("<I", value_sub) + struct.pack("<I", value) + str_bytes + str_sub_bytes
    return _payload_header(len(data), channel, sign_code) + data


def build_talkback_audio_frame(
    audio_data: bytes,
    video_seq: int,
    channel: int = 0,
) -> bytes:
    """Build a complete talkback audio frame for sending audio TO the device.

    Returns the full UDP DATA payload (without the F1 D0 envelope).
    """
    # Command header: [D1 01] [seq(2B BE)] [XZYH] [CMD_AUDIO_FRAME(2B LE)]
    cmd_header = (
        struct.pack(">H", P2PDataType.VIDEO)
        + struct.pack(">H", video_seq)
        + MAGIC_WORD
        + struct.pack("<H", 1301)  # CMD_AUDIO_FRAME
    )

    # Audio data header (16 bytes)
    audio_data_header = (
        struct.pack("<I", len(audio_data))  # audio data length
        + b"\x00"                            # unknown
        + b"\x00"                            # audio type (AAC)
        + b"\x00\x00"                        # audio sequence
        + b"\x00" * 8                        # timestamp
    )

    # Talkback frame header
    frame_header = (
        struct.pack("<I", len(audio_data) + len(audio_data_header))  # bytes_to_read
        + b"\x01\x00"                  # magic
        + bytes([channel, 0x00])       # channel + padding
        + b"\x00\x00"                  # empty
        + audio_data_header
    )

    return cmd_header + frame_header + audio_data


def build_command_void(channel: int = 255, sign_code: int = 0) -> bytes:
    """Build a 'WithoutData' (void) command payload — just the 10-byte header.

    Default channel=255 for station-level commands (CMD_GATEWAYINFO, CMD_PING).
    """
    return _payload_header(0, channel, sign_code)


def build_data_message(
    data_type: int,
    sequence: int,
    command_type: int,
    payload: bytes = b"",
) -> bytes:
    """Build a complete DATA (F1 D0) packet with full 16-byte XZYH header.

    Outgoing wire format:
      [F1 D0] [total_len(2,BE)]
      [data_type(2,BE)] [seq(2,BE)]
      [XZYH(4)] [cmd(2,LE)] [bytes_to_read(4,LE)] [pad(2)] [ch(1)] [sign(1)] [type(1)] [pad(1)]
      [payload_with_10byte_header...]

    The channel and sign_code are extracted from the 10-byte payload header
    (bytes [6] and [7]) and placed into the XZYH header. The sign_code in
    the payload data is cleared to 0 (it belongs in the XZYH header only).
    """
    # Extract channel and sign_code from the 10-byte payload header
    channel = payload[6] if len(payload) > 6 else 0
    sign_code = payload[7] if len(payload) > 7 else 0

    # Clear sign_code in payload data — it's in the XZYH header instead
    if sign_code > 0 and len(payload) > 7:
        payload = payload[:7] + b"\x00" + payload[8:]

    inner = (
        struct.pack(">H", data_type)
        + struct.pack(">H", sequence)
        + MAGIC_WORD
        + struct.pack("<H", command_type)
        + struct.pack("<I", len(payload))   # bytes_to_read
        + b"\x00\x00"                       # padding
        + bytes([channel])                   # channel
        + bytes([sign_code])                 # sign_code
        + b"\x00"                            # type (0 = request)
        + b"\x00"                            # padding
        + payload
    )

    return build_udp_packet(P2PMessageType.DATA, inner)


# ---------------------------------------------------------------------------
# Address parsing helpers
# ---------------------------------------------------------------------------

def parse_lookup_addr(payload: bytes) -> tuple[str, int] | None:
    """Parse a LOOKUP_ADDR (F1 40) response payload (header already stripped).

    The 4-byte UDP header (msg_type + length) is stripped by UDPPacket.parse().
    Payload layout:
      [0-1] splitter (0x00 0x02)
      [2-3] port (uint16 LE)
      [4-7] IP (reversed byte order: [7].[6].[5].[4])
    """
    if len(payload) < 8:
        return None
    port = struct.unpack("<H", payload[2:4])[0]
    ip = f"{payload[7]}.{payload[6]}.{payload[5]}.{payload[4]}"
    return (ip, port)


def parse_lookup_addr2(payload: bytes) -> tuple[tuple[str, int], bytes] | None:
    """Parse a LOOKUP_ADDR2 (F1 82) response payload (header already stripped).

    Payload layout:
      [0-1] splitter
      [2-3] port (uint16 LE)
      [4-7] IP (reversed byte order)
      [8-15] padding
      [16-19] TURN data token
    """
    if len(payload) < 20:
        return None
    port = struct.unpack("<H", payload[2:4])[0]
    ip = f"{payload[7]}.{payload[6]}.{payload[5]}.{payload[4]}"
    data_token = payload[16:20]
    return ((ip, port), data_token)


def parse_cam_id(payload: bytes) -> str:
    """Parse a CAM_ID (F1 42) response to extract the p2p_did."""
    if len(payload) < 20:
        return ""
    from ..crypto import bytes_to_p2p_did
    return bytes_to_p2p_did(payload[4:24])
