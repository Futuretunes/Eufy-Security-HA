"""Tests for the P2P protocol module."""

import struct
import pytest

from custom_components.eufy_security_advanced.lib.p2p.protocol import (
    AudioFrameHeader,
    DataMessage,
    UDPPacket,
    VideoFrameHeader,
    XZYHHeader,
    MAGIC_WORD,
    build_ack,
    build_check_cam,
    build_command_payload_int,
    build_command_payload_int_string,
    build_command_payload_json,
    build_command_payload_string,
    build_command_void,
    build_data_message,
    build_end,
    build_local_lookup,
    build_ping,
    build_pong,
    build_talkback_audio_frame,
    build_udp_packet,
    parse_lookup_addr,
    parse_lookup_addr2,
)
from custom_components.eufy_security_advanced.lib.types import P2PMessageType, P2PDataType


class TestUDPPacket:
    """Test UDP packet parsing and encoding."""

    def test_encode_decode_roundtrip(self):
        pkt = UDPPacket(msg_type=0xF1D0, payload=b"hello")
        encoded = pkt.encode()
        decoded = UDPPacket.parse(encoded)
        assert decoded is not None
        assert decoded.msg_type == 0xF1D0
        assert decoded.payload == b"hello"

    def test_parse_too_short(self):
        assert UDPPacket.parse(b"\x00") is None
        assert UDPPacket.parse(b"") is None

    def test_encode_format(self):
        pkt = UDPPacket(msg_type=0xF1E0, payload=b"\x01\x02")
        data = pkt.encode()
        assert data[:2] == b"\xf1\xe0"
        assert struct.unpack(">H", data[2:4])[0] == 2
        assert data[4:] == b"\x01\x02"


class TestDataMessage:
    def test_parse(self):
        payload = (
            struct.pack(">H", 100)       # bytes_to_read
            + struct.pack(">H", 0xD100)  # data_type
            + struct.pack(">H", 42)      # sequence
            + b"payload_data"
        )
        msg = DataMessage.parse(payload)
        assert msg is not None
        assert msg.bytes_to_read == 100
        assert msg.data_type == 0xD100
        assert msg.sequence == 42
        assert msg.data == b"payload_data"

    def test_parse_too_short(self):
        assert DataMessage.parse(b"\x00") is None


class TestXZYHHeader:
    def test_parse(self):
        header = (
            MAGIC_WORD                         # "XZYH"
            + struct.pack("<H", 1300)          # command_id
            + struct.pack("<I", 65536)         # bytes_to_read
            + b"\x00\x00"                      # padding
            + bytes([0])                       # channel
            + bytes([1])                       # sign_code
            + bytes([1])                       # msg_type (response)
            + b"\x00"                          # padding
        )
        parsed = XZYHHeader.parse(header)
        assert parsed is not None
        assert parsed.command_id == 1300
        assert parsed.bytes_to_read == 65536
        assert parsed.channel == 0
        assert parsed.sign_code == 1
        assert parsed.msg_type == 1

    def test_parse_wrong_magic(self):
        assert XZYHHeader.parse(b"ABCD" + b"\x00" * 12) is None

    def test_parse_too_short(self):
        assert XZYHHeader.parse(MAGIC_WORD + b"\x00" * 5) is None


class TestVideoFrameHeader:
    def test_parse(self):
        data = (
            struct.pack("<I", 1024)     # data_length
            + bytes([1])                # is_keyframe
            + bytes([1])                # stream_type (H264)
            + struct.pack("<H", 10)     # sequence
            + struct.pack("<H", 30)     # fps
            + struct.pack("<H", 1920)   # width
            + struct.pack("<H", 1080)   # height
            + b"\x00" * 6              # timestamp
            + b"\x00" * 2              # padding
        )
        vf = VideoFrameHeader.parse(data)
        assert vf is not None
        assert vf.data_length == 1024
        assert vf.is_keyframe is True
        assert vf.stream_type == 1
        assert vf.fps == 30
        assert vf.width == 1920
        assert vf.height == 1080


class TestAudioFrameHeader:
    def test_parse(self):
        data = (
            struct.pack("<I", 512)      # data_length
            + bytes([0])                # padding
            + bytes([1])                # audio_type (AAC_LC)
            + struct.pack("<H", 5)      # sequence
            + b"\x00" * 6              # timestamp
            + b"\x00" * 2              # padding
        )
        af = AudioFrameHeader.parse(data)
        assert af is not None
        assert af.data_length == 512
        assert af.audio_type == 1
        assert af.sequence == 5


class TestPacketBuilders:
    def test_build_ping(self):
        pkt = build_ping(b"\x01\x02")
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.PING
        assert parsed.payload == b"\x01\x02"

    def test_build_pong(self):
        pkt = build_pong()
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.PONG

    def test_build_end(self):
        pkt = build_end()
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.END

    def test_build_local_lookup(self):
        pkt = build_local_lookup()
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.LOCAL_LOOKUP
        assert parsed.payload == b"\x00\x00"

    def test_build_ack(self):
        pkt = build_ack(P2PDataType.DATA, 42)
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.ACK
        # Payload: [data_type(2B)] [count(2B)] [seq(2B)]
        assert len(parsed.payload) == 6
        assert struct.unpack(">H", parsed.payload[4:6])[0] == 42


class TestCommandPayloads:
    def test_void_payload(self):
        payload = build_command_void(channel=5)
        assert len(payload) == 10
        assert payload[6] == 5  # channel byte

    def test_int_payload(self):
        payload = build_command_payload_int(42, channel=0)
        # 10 byte header + 4 byte int + 128 byte string
        assert len(payload) == 10 + 4 + 128
        value = struct.unpack("<I", payload[10:14])[0]
        assert value == 42

    def test_int_string_payload(self):
        payload = build_command_payload_int_string(
            value=1, value_sub=2, str_value="test", channel=3
        )
        # 10 byte header + 4 + 4 + 128 + 128
        assert len(payload) == 10 + 4 + 4 + 128 + 128
        value_sub = struct.unpack("<I", payload[10:14])[0]
        value = struct.unpack("<I", payload[14:18])[0]
        assert value_sub == 2
        assert value == 1

    def test_json_payload(self):
        json_str = '{"test": true}'
        payload = build_command_payload_json(json_str, channel=255)
        # 10 byte header + json bytes
        assert len(payload) == 10 + len(json_str.encode())
        assert payload[6] == 255  # channel

    def test_string_payload(self):
        payload = build_command_payload_string("hello", "world")
        # 10 byte header + 5 zero bytes + 128 + 128
        assert len(payload) == 10 + 5 + 128 + 128


class TestTalkbackFrame:
    def test_build_frame(self):
        audio = b"\xff" * 64
        frame = build_talkback_audio_frame(audio, video_seq=10, channel=0)
        # 10 (cmd header) + 10 (frame header) + 16 (audio data header) + 64 (audio)
        assert len(frame) == 10 + 10 + 16 + 64
        # Check magic word at offset 4
        assert frame[4:8] == MAGIC_WORD
        # Check command type at offset 8 (CMD_AUDIO_FRAME = 1301)
        cmd_type = struct.unpack("<H", frame[8:10])[0]
        assert cmd_type == 1301


class TestAddressParsing:
    def test_parse_lookup_addr(self):
        # Build a payload: 6 padding bytes + port(2B LE) + ip(4B reversed)
        payload = b"\x00" * 6
        payload += struct.pack("<H", 32100)
        payload += bytes([1, 168, 192, 10])  # reversed: 10.192.168.1
        result = parse_lookup_addr(payload)
        assert result == ("10.192.168.1", 32100)

    def test_parse_lookup_addr_too_short(self):
        assert parse_lookup_addr(b"\x00" * 5) is None

    def test_parse_lookup_addr2(self):
        payload = b"\x00" * 6
        payload += struct.pack("<H", 32100)
        payload += bytes([1, 0, 0, 127])  # reversed: 127.0.0.1
        payload += b"\x00" * 8  # padding to offset 20
        payload += b"\xAB\xCD\xEF\x01"  # data token
        result = parse_lookup_addr2(payload)
        assert result is not None
        (ip, port), token = result
        assert ip == "127.0.0.1"
        assert port == 32100
        assert token == b"\xAB\xCD\xEF\x01"


class TestDataMessage:
    def test_build_data_message(self):
        payload = build_command_void()
        pkt = build_data_message(P2PDataType.DATA, 0, 1100, payload)
        parsed = UDPPacket.parse(pkt)
        assert parsed.msg_type == P2PMessageType.DATA
        # The envelope should contain XZYH
        assert MAGIC_WORD in parsed.payload
