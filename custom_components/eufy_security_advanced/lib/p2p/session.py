"""Eufy P2P UDP session — connection, commands, and streaming."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import struct
import time
from collections import defaultdict
from typing import Any, Callable

from ..crypto import (
    decrypt_p2p,
    decrypt_video_frame,
    derive_p2p_key_level1,
    derive_p2p_key_level2,
    encrypt_p2p,
    generate_rsa_keypair,
    p2p_did_to_bytes,
)
from ..models import P2PSessionData, StreamData
from ..types import (
    AudioCodec,
    CommandType,
    P2PConnectionMode,
    P2PDataType,
    P2PEncryptionLevel,
    P2PMessageType,
    VideoCodec,
)
from .protocol import (
    MAGIC_WORD,
    AudioFrameHeader,
    DataMessage,
    UDPPacket,
    VideoFrameHeader,
    XZYHHeader,
    build_ack,
    build_check_cam,
    build_command_payload_int,
    build_command_payload_json,
    build_command_void,
    build_data_message,
    build_end,
    build_local_lookup,
    build_lookup_with_key,
    build_lookup_with_key2,
    build_ping,
    build_pong,
    build_udp_packet,
    parse_cam_id,
    parse_lookup_addr,
    parse_lookup_addr2,
)

_LOGGER = logging.getLogger(__name__)

# Timeouts
CONNECT_TIMEOUT = 25.0
LOOKUP_TIMEOUT = 20.0
HEARTBEAT_INTERVAL = 5.0
HEARTBEAT_MAX_MISS = 10
KEEPALIVE_INTERVAL = 2.0
COMMAND_RETRY_INTERVAL = 0.1
COMMAND_TIMEOUT = 5.0
COMMAND_MAX_RETRIES = 10
COMMAND_RESULT_TIMEOUT = 30.0
STREAM_DATA_TIMEOUT = 20.0
AUDIO_DETECT_TIMEOUT = 0.65
MAX_FRAME_SIZE = 655_360


class P2PSession:
    """Manages a P2P UDP session with a Eufy station."""

    def __init__(
        self,
        station_sn: str,
        p2p_did: str,
        dsk_key: str,
        cloud_ips: list[tuple[str, int]],
        local_ip: str = "",
        admin_user_id: str = "",
        connection_mode: P2PConnectionMode = P2PConnectionMode.QUICKEST,
        get_cipher_callback: Callable | None = None,
    ) -> None:
        self._station_sn = station_sn
        self._p2p_did = p2p_did
        self._p2p_did_bytes = p2p_did_to_bytes(p2p_did)
        self._dsk_key = dsk_key
        self._cloud_ips = cloud_ips
        self._local_ip = local_ip or self._get_local_ip()
        self._admin_user_id = admin_user_id
        self._connection_mode = connection_mode
        self._get_cipher = get_cipher_callback

        # Socket
        self._sock: socket.socket | None = None
        self._local_port = 0

        # Connection state
        self._connected = False
        self._connect_address: tuple[str, int] | None = None
        self._is_local = False

        # Encryption
        self._encryption_level = P2PEncryptionLevel.NONE
        self._p2p_key: bytes = b""
        self._rsa_private_key, self._rsa_public_key = generate_rsa_keypair()

        # Sequence tracking
        self._send_sequence = 0
        self._expected_seq: dict[int, int] = defaultdict(int)
        self._reassembly: dict[int, dict[int, bytes]] = defaultdict(dict)
        self._reassembly_total: dict[int, int] = defaultdict(int)
        self._reassembly_received: dict[int, int] = defaultdict(int)

        # Command tracking
        self._pending_commands: dict[int, asyncio.Future] = {}
        self._command_results: dict[int, asyncio.Future] = {}

        # Heartbeat
        self._last_pong_data: bytes = b""
        self._missed_pongs = 0

        # Streaming
        self._video_codec = VideoCodec.UNKNOWN
        self._audio_codec = AudioCodec.UNKNOWN
        self._is_streaming = False
        self._got_keyframe = False

        # Callbacks
        self._on_stream_data: Callable[[StreamData], None] | None = None
        self._on_disconnect: Callable[[], None] | None = None
        self._on_event: Callable[[int, dict[str, Any]], None] | None = None

        # Tasks
        self._recv_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None

    @staticmethod
    def _get_local_ip() -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def is_streaming(self) -> bool:
        return self._is_streaming

    def set_stream_callback(self, callback: Callable[[StreamData], None]) -> None:
        self._on_stream_data = callback

    def set_disconnect_callback(self, callback: Callable[[], None]) -> None:
        self._on_disconnect = callback

    def set_event_callback(self, callback: Callable[[int, dict[str, Any]], None]) -> None:
        self._on_event = callback

    # ----- Connection -----

    async def connect(self) -> bool:
        """Establish P2P connection via lookup + NAT hole-punching."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1_048_576)
        self._sock.setblocking(False)
        self._sock.bind(("", 0))
        self._local_port = self._sock.getsockname()[1]

        _LOGGER.debug(
            "P2P connecting to %s (DID: %s) from port %d",
            self._station_sn, self._p2p_did, self._local_port,
        )

        loop = asyncio.get_event_loop()
        connected_event = asyncio.Event()

        # Start receiver
        self._recv_task = asyncio.create_task(
            self._receive_loop(connected_event)
        )

        # Run lookup strategies in parallel
        lookup_tasks = []

        if self._connection_mode != P2PConnectionMode.ONLY_LOCAL:
            lookup_tasks.append(
                asyncio.create_task(self._cloud_lookup(loop))
            )
        if self._connection_mode != P2PConnectionMode.ONLY_LOCAL:
            # Delayed v2 lookup
            lookup_tasks.append(
                asyncio.create_task(self._cloud_lookup_v2_delayed(loop))
            )

        lookup_tasks.append(
            asyncio.create_task(self._local_lookup(loop))
        )

        try:
            await asyncio.wait_for(connected_event.wait(), CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            _LOGGER.warning("P2P connection timed out for %s", self._station_sn)
            await self.disconnect()
            return False
        finally:
            for task in lookup_tasks:
                task.cancel()

        # Connection established
        self._connected = True
        self._gateway_ready = asyncio.Event()
        _LOGGER.info(
            "P2P connected to %s at %s (local=%s)",
            self._station_sn, self._connect_address, self._is_local,
        )

        # Start heartbeat
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        # Send gateway info to negotiate encryption and wait for response
        await self._send_gateway_info()
        try:
            await asyncio.wait_for(self._gateway_ready.wait(), timeout=10.0)
            _LOGGER.info("P2P handshake complete for %s", self._station_sn)
        except asyncio.TimeoutError:
            _LOGGER.warning("P2P gateway info timeout for %s — proceeding without encryption", self._station_sn)
            self._gateway_ready.set()  # Allow commands anyway

        return True

    async def disconnect(self) -> None:
        """Close the P2P connection."""
        if self._connected and self._sock and self._connect_address:
            try:
                end_pkt = build_end()
                self._sock.sendto(end_pkt, self._connect_address)
            except Exception:
                pass

        self._connected = False
        self._is_streaming = False

        for task in (self._recv_task, self._heartbeat_task, self._keepalive_task):
            if task and not task.done():
                task.cancel()

        if self._sock:
            self._sock.close()
            self._sock = None

        if self._on_disconnect:
            self._on_disconnect()

    def _send_to(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        """Send raw bytes via the UDP socket."""
        if not self._sock:
            return
        target = addr or self._connect_address
        if target:
            try:
                self._sock.sendto(data, target)
            except OSError as e:
                _LOGGER.debug("Send error: %s", e)

    def _next_sequence(self) -> int:
        """Get next send sequence number (wrapping uint16)."""
        seq = self._send_sequence
        self._send_sequence = (self._send_sequence + 1) & 0xFFFF
        return seq

    # ----- Lookup strategies -----

    async def _cloud_lookup(self, loop: asyncio.AbstractEventLoop) -> None:
        """Cloud lookup v1 — send LOOKUP_WITH_KEY to cloud servers."""
        while not self._connected:
            for ip, port in self._cloud_ips:
                pkt = build_lookup_with_key(
                    self._p2p_did_bytes, self._local_port, self._local_ip, self._dsk_key
                )
                self._send_to(pkt, (ip, port))
            await asyncio.sleep(1.0)

    async def _cloud_lookup_v2_delayed(self, loop: asyncio.AbstractEventLoop) -> None:
        """Cloud lookup v2 — starts 3s after initial, retries every 1s."""
        await asyncio.sleep(3.0)
        while not self._connected:
            for ip, port in self._cloud_ips:
                pkt = build_lookup_with_key2(self._p2p_did_bytes, self._dsk_key)
                self._send_to(pkt, (ip, port))
            await asyncio.sleep(1.0)

    async def _local_lookup(self, loop: asyncio.AbstractEventLoop) -> None:
        """Local LAN broadcast discovery."""
        broadcast_addr = self._local_ip.rsplit(".", 1)[0] + ".255"
        while not self._connected:
            pkt = build_local_lookup()
            self._send_to(pkt, (broadcast_addr, 32108))
            await asyncio.sleep(1.0)

    def _send_check_cam(self, addr: tuple[str, int]) -> None:
        """Send CHECK_CAM to target address + port range [-3, +3]."""
        pkt = build_check_cam(self._p2p_did_bytes)
        ip, base_port = addr
        for offset in range(-3, 4):
            port = base_port + offset
            if 0 < port < 65536:
                self._send_to(pkt, (ip, port))

    # ----- Receive loop -----

    async def _receive_loop(self, connected_event: asyncio.Event) -> None:
        """Main receive loop — processes all incoming UDP packets."""
        loop = asyncio.get_event_loop()

        while self._sock is not None:
            try:
                data, addr = await loop.sock_recvfrom(self._sock, 1_048_576)
            except (OSError, asyncio.CancelledError):
                break

            if len(data) < 4:
                continue

            pkt = UDPPacket.parse(data)
            if not pkt:
                continue

            try:
                await self._handle_packet(pkt, addr, connected_event)
            except Exception:
                _LOGGER.debug("Error handling packet type 0x%04X", pkt.msg_type, exc_info=True)

    async def _handle_packet(
        self,
        pkt: UDPPacket,
        addr: tuple[str, int],
        connected_event: asyncio.Event,
    ) -> None:
        """Dispatch a received packet by type."""
        mt = pkt.msg_type

        # ----- Lookup responses (only before connected!) -----
        if mt == P2PMessageType.LOOKUP_ADDR:
            if not self._connected:
                result = parse_lookup_addr(pkt.payload)
                if result:
                    _LOGGER.debug("LOOKUP_ADDR: %s", result)
                    self._send_check_cam(result)

        elif mt == P2PMessageType.LOOKUP_ADDR2:
            if not self._connected:
                result = parse_lookup_addr2(pkt.payload)
                if result:
                    (ip, port), token = result
                    _LOGGER.debug("LOOKUP_ADDR2: %s:%d token=%s", ip, port, token.hex())
                    self._send_check_cam((ip, port))

        elif mt == 0xF141 and not self._connected:
            # LOCAL_LOOKUP_RESP or CAM_ID — check p2p_did
            if len(pkt.payload) >= 24:
                from ..crypto import bytes_to_p2p_did
                resp_did = bytes_to_p2p_did(pkt.payload[4:24])
                if resp_did == self._p2p_did:
                    _LOGGER.debug("Local device found at %s", addr)
                    self._send_check_cam(addr)

        # ----- Connection established -----
        elif mt == P2PMessageType.CAM_ID or mt == P2PMessageType.TURN_SERVER_CAM_ID:
            if not self._connected:
                self._connect_address = addr
                self._is_local = mt != P2PMessageType.TURN_SERVER_CAM_ID
                connected_event.set()

        # ----- Heartbeat -----
        elif mt == P2PMessageType.PONG:
            self._missed_pongs = 0
            self._last_pong_data = pkt.payload

        elif mt == P2PMessageType.PING:
            self._send_to(build_pong(pkt.payload))

        # ----- Data -----
        elif mt == P2PMessageType.DATA:
            await self._handle_data(pkt.payload)

        elif mt == P2PMessageType.ACK:
            self._handle_ack(pkt.payload)

        # ----- End -----
        elif mt == P2PMessageType.END:
            _LOGGER.info("Received END from %s", self._station_sn)
            await self.disconnect()

    # ----- Data handling -----

    async def _handle_data(self, payload: bytes) -> None:
        """Handle a DATA (F1 D0) message."""
        msg = DataMessage.parse(payload)
        if not msg:
            return

        # Send ACK immediately
        ack = build_ack(msg.data_type, msg.sequence)
        self._send_to(ack)

        # Check for duplicates
        expected = self._expected_seq[msg.data_type]
        if msg.sequence != expected:
            diff = (msg.sequence - expected) & 0xFFFF
            if diff > 0x7FFF:
                # Already processed (behind expected)
                return
            # Out of order — store for later
            self._reassembly[msg.data_type][msg.sequence] = msg.data
            return

        # In-order: process this and any buffered continuations
        self._expected_seq[msg.data_type] = (msg.sequence + 1) & 0xFFFF
        await self._process_data_segment(msg.data_type, msg.data)

        # Drain buffered segments
        while (self._expected_seq[msg.data_type]) in self._reassembly.get(msg.data_type, {}):
            next_seq = self._expected_seq[msg.data_type]
            buffered = self._reassembly[msg.data_type].pop(next_seq)
            self._expected_seq[msg.data_type] = (next_seq + 1) & 0xFFFF
            await self._process_data_segment(msg.data_type, buffered)

    async def _process_data_segment(self, data_type: int, data: bytes) -> None:
        """Process an in-order data segment, handling reassembly of multi-part messages."""
        # Check if this starts a new logical message (has XZYH header)
        if len(data) >= 16 and data[:4] == MAGIC_WORD:
            header = XZYHHeader.parse(data[:16])
            if header:
                msg_data = data[16:]
                total = header.bytes_to_read

                if len(msg_data) >= total:
                    # Complete message in one segment
                    await self._dispatch_message(
                        data_type, header, msg_data[:total]
                    )
                else:
                    # Multi-part: store for reassembly
                    key = (data_type, header.command_id)
                    self._reassembly_total[data_type] = total
                    self._reassembly_received[data_type] = len(msg_data)
                    self._reassembly[1000 + data_type] = {0: msg_data}
                    # Store header for later
                    self._reassembly[2000 + data_type] = {0: data[:16]}
                return

        # Continuation of multi-part message
        if data_type in self._reassembly_total:
            existing = self._reassembly.get(1000 + data_type, {})
            idx = len(existing)
            existing[idx] = data
            self._reassembly[1000 + data_type] = existing
            self._reassembly_received[data_type] += len(data)

            if self._reassembly_received[data_type] >= self._reassembly_total[data_type]:
                # Reassembly complete
                header_data = self._reassembly.get(2000 + data_type, {}).get(0, b"")
                header = XZYHHeader.parse(header_data) if header_data else None
                parts = self._reassembly.pop(1000 + data_type, {})
                full_data = b"".join(parts[k] for k in sorted(parts.keys()))
                del self._reassembly_total[data_type]
                del self._reassembly_received[data_type]
                self._reassembly.pop(2000 + data_type, None)

                if header:
                    await self._dispatch_message(
                        data_type, header, full_data[:header.bytes_to_read]
                    )

    async def _dispatch_message(
        self, data_type: int, header: XZYHHeader, data: bytes
    ) -> None:
        """Dispatch a fully reassembled message."""
        # Decrypt if needed
        if header.sign_code > 0 and self._p2p_key:
            if data_type == P2PDataType.CONTROL:
                key = derive_p2p_key_level1(self._station_sn, self._p2p_did)
                data = decrypt_p2p(data, key)
            elif data_type == P2PDataType.DATA:
                data = decrypt_p2p(data, self._p2p_key)

        cmd = header.command_id

        # ----- CONTROL messages -----
        if data_type == P2PDataType.CONTROL:
            if cmd == CommandType.CMD_GATEWAYINFO:
                await self._handle_gateway_info(data)
            elif cmd == CommandType.CMD_CAMERA_INFO:
                self._handle_camera_info(data)
            elif cmd == CommandType.CMD_NOTIFY_PAYLOAD:
                self._handle_notify_payload(data)
            else:
                _LOGGER.debug("Control message cmd=%d len=%d", cmd, len(data))

        # ----- VIDEO stream -----
        elif data_type == P2PDataType.VIDEO:
            if cmd == CommandType.CMD_VIDEO_FRAME:
                self._handle_video_frame(data, header.sign_code)
            elif cmd == CommandType.CMD_AUDIO_FRAME:
                self._handle_audio_frame(data)

        # ----- DATA command responses -----
        elif data_type == P2PDataType.DATA:
            # Check if this is a response to a pending command
            if cmd in self._command_results:
                fut = self._command_results.pop(cmd)
                if not fut.done():
                    fut.set_result(data)
            elif self._on_event:
                try:
                    payload = json.loads(data.decode("utf-8", errors="replace").rstrip("\x00"))
                    self._on_event(cmd, payload)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

    # ----- Gateway info (encryption negotiation) -----

    async def _send_gateway_info(self) -> None:
        """Send CMD_GATEWAYINFO to negotiate encryption."""
        payload = build_command_void(channel=255)  # 255 = station channel
        seq = self._next_sequence()
        pkt = build_data_message(
            P2PDataType.DATA, seq, CommandType.CMD_GATEWAYINFO, payload
        )
        _LOGGER.debug("Sending CMD_GATEWAYINFO seq=%d (%d bytes): %s", seq, len(pkt), pkt.hex())
        self._send_to(pkt)

    async def _handle_gateway_info(self, data: bytes) -> None:
        """Process the gateway info response to establish encryption."""
        _LOGGER.info("Gateway info response received (%d bytes)", len(data))

        if len(data) < 4:
            _LOGGER.debug("Gateway info too short, using no encryption")
            self._encryption_level = P2PEncryptionLevel.NONE
            if hasattr(self, "_gateway_ready"):
                self._gateway_ready.set()
            return

        cipher_id = struct.unpack("<H", data[0:2])[0]
        _LOGGER.debug("Gateway cipher_id=%d", cipher_id)

        # Try Level 2 first (RSA + AES)
        if cipher_id > 0 and self._get_cipher:
            try:
                ciphers = await self._get_cipher([cipher_id], self._admin_user_id)
                rsa_key_pem = ciphers.get(cipher_id, "")
                if rsa_key_pem:
                    encrypted_key = data[4:].split(b"\x00")[0]
                    if encrypted_key:
                        self._p2p_key = derive_p2p_key_level2(encrypted_key, rsa_key_pem)
                        self._encryption_level = P2PEncryptionLevel.LEVEL_2
                        _LOGGER.info("P2P encryption: Level 2 (RSA+AES)")
                        if hasattr(self, "_gateway_ready"):
                            self._gateway_ready.set()
                        return
            except Exception:
                _LOGGER.debug("Level 2 encryption setup failed", exc_info=True)

        # Fall back to Level 1
        try:
            self._p2p_key = derive_p2p_key_level1(self._station_sn, self._p2p_did)
            self._encryption_level = P2PEncryptionLevel.LEVEL_1
            _LOGGER.info("P2P encryption: Level 1 (derived key)")
        except Exception:
            self._encryption_level = P2PEncryptionLevel.NONE
            _LOGGER.info("P2P encryption: None")

        if hasattr(self, "_gateway_ready"):
            self._gateway_ready.set()

    def _handle_camera_info(self, data: bytes) -> None:
        """Handle camera info parameters."""
        try:
            text = data.decode("utf-8", errors="replace").rstrip("\x00")
            params = json.loads(text)
            if self._on_event:
                self._on_event(CommandType.CMD_CAMERA_INFO, params)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    def _handle_notify_payload(self, data: bytes) -> None:
        """Handle device notification payloads."""
        try:
            text = data.decode("utf-8", errors="replace").rstrip("\x00")
            payload = json.loads(text)
            if self._on_event:
                self._on_event(CommandType.CMD_NOTIFY_PAYLOAD, payload)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

    # ----- Video/Audio streaming -----

    def _handle_video_frame(self, data: bytes, sign_code: int) -> None:
        """Handle a video frame."""
        vf = VideoFrameHeader.parse(data)
        if not vf:
            return

        video_data = data[22:]  # After the 22-byte video header

        # Decrypt if encrypted (RSA per-frame encryption)
        if sign_code > 0 and len(video_data) >= 128:
            video_data = decrypt_video_frame(data, self._rsa_private_key)

        if not video_data or len(video_data) > MAX_FRAME_SIZE:
            return

        # Detect codec
        if self._video_codec == VideoCodec.UNKNOWN:
            if vf.stream_type == 1:
                self._video_codec = VideoCodec.H264
            elif vf.stream_type == 2:
                self._video_codec = VideoCodec.H265
            else:
                self._video_codec = self._detect_video_codec(video_data)

        # Wait for keyframe before streaming
        if not self._got_keyframe:
            if vf.is_keyframe:
                self._got_keyframe = True
                _LOGGER.info(
                    "VIDEO: streaming %dx%d %dfps %s",
                    vf.width, vf.height, vf.fps, self._video_codec.name,
                )
            else:
                return

        if self._on_stream_data:
            self._on_stream_data(StreamData(
                is_video=True,
                codec=self._video_codec,
                data=video_data,
                is_keyframe=vf.is_keyframe,
                width=vf.width,
                height=vf.height,
                fps=vf.fps,
                sequence=vf.sequence,
                timestamp=vf.timestamp,
            ))

    def _handle_audio_frame(self, data: bytes) -> None:
        """Handle an audio frame."""
        af = AudioFrameHeader.parse(data)
        if not af:
            return

        audio_data = data[16:]  # After the 16-byte audio header

        # Detect codec
        if self._audio_codec == AudioCodec.UNKNOWN:
            if af.audio_type == 0:
                self._audio_codec = AudioCodec.AAC
            elif af.audio_type == 1:
                self._audio_codec = AudioCodec.AAC_LC
            elif af.audio_type == 7:
                self._audio_codec = AudioCodec.AAC_ELD
            else:
                self._audio_codec = AudioCodec.AAC

        if self._on_stream_data:
            self._on_stream_data(StreamData(
                is_video=False,
                codec=self._audio_codec,
                data=audio_data,
                sequence=af.sequence,
                timestamp=af.timestamp,
            ))

    @staticmethod
    def _detect_video_codec(data: bytes) -> VideoCodec:
        """Detect video codec from NAL unit start codes."""
        # Look for start code 00 00 01 or 00 00 00 01
        for offset in (3, 4):
            if len(data) > offset:
                nal_type = data[offset] & 0x1F
                if nal_type == 0x07:  # SPS = H.264
                    return VideoCodec.H264
                if (data[offset] >> 1) & 0x3F in (32, 33, 34):  # H.265 VPS/SPS/PPS
                    return VideoCodec.H265
        return VideoCodec.H264  # Default

    # ----- ACK handling -----

    def _handle_ack(self, payload: bytes) -> None:
        """Handle an ACK for a sent command."""
        if len(payload) < 6:
            return
        num_acks = struct.unpack(">H", payload[2:4])[0]
        for i in range(num_acks):
            offset = 4 + i * 2
            if offset + 2 <= len(payload):
                seq = struct.unpack(">H", payload[offset : offset + 2])[0]
                if seq in self._pending_commands:
                    fut = self._pending_commands.pop(seq)
                    if not fut.done():
                        fut.set_result(True)

    # ----- Heartbeat -----

    async def _heartbeat_loop(self) -> None:
        """Send periodic PING packets."""
        while self._connected:
            try:
                self._send_to(build_ping(self._last_pong_data))
                self._missed_pongs += 1

                if self._missed_pongs >= HEARTBEAT_MAX_MISS:
                    _LOGGER.warning("P2P heartbeat timeout for %s", self._station_sn)
                    await self.disconnect()
                    return

                await asyncio.sleep(HEARTBEAT_INTERVAL)
            except asyncio.CancelledError:
                return

    # ----- Public command API -----

    async def send_command(
        self,
        command_type: int,
        payload: bytes = b"",
        data_type: int = P2PDataType.DATA,
    ) -> bytes | None:
        """Send a command and wait for ACK + result.

        The payload should already include the 10-byte header from the
        payload builders (channel, sign_code, etc. are embedded in it).
        Returns the command result data, or None on timeout.
        """
        if not self._connected:
            raise ConnectionError("Not connected")

        # Note: outgoing command payloads are NOT encrypted by default.
        # The TypeScript client only encrypts when signCode != 0, which is
        # only for specific sensitive commands (lock payloads, etc.).
        # Normal commands like CMD_START_REALTIME_MEDIA use signCode=0.

        seq = self._next_sequence()
        pkt = build_data_message(data_type, seq, command_type, payload)


        # Wait for ACK
        ack_future: asyncio.Future[bool] = asyncio.get_event_loop().create_future()
        self._pending_commands[seq] = ack_future

        # Wait for result
        result_future: asyncio.Future[bytes] = asyncio.get_event_loop().create_future()
        self._command_results[command_type] = result_future

        # Send with retries
        for attempt in range(COMMAND_MAX_RETRIES):
            self._send_to(pkt)
            try:
                await asyncio.wait_for(asyncio.shield(ack_future), COMMAND_RETRY_INTERVAL)
                break
            except asyncio.TimeoutError:
                if attempt == COMMAND_MAX_RETRIES - 1:
                    self._pending_commands.pop(seq, None)
                    self._command_results.pop(command_type, None)
                    _LOGGER.warning("Command %d: ACK timeout", command_type)
                    return None

        # Wait for result
        try:
            result = await asyncio.wait_for(result_future, COMMAND_RESULT_TIMEOUT)
            return result
        except asyncio.TimeoutError:
            self._command_results.pop(command_type, None)
            return None

    # ----- Livestream -----

    async def start_livestream(self, channel: int = 0) -> bool:
        """Start live video stream.

        For battery doorbells via HomeBase, uses CMD_SET_PAYLOAD wrapping
        CMD_START_REALTIME_MEDIA as JSON with RSA public key for video
        encryption. The payload is AES-encrypted when P2P encryption is active.
        """
        self._is_streaming = True
        self._got_keyframe = False
        self._video_codec = VideoCodec.UNKNOWN
        self._audio_codec = AudioCodec.UNKNOWN

        # Build JSON payload with RSA public key for video encryption
        rsa_key_hex = format(self._rsa_public_key.n, '0256x')
        payload_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_START_REALTIME_MEDIA,
            "mValue3": CommandType.CMD_START_REALTIME_MEDIA,
            "payload": {
                "ClientOS": "Android",
                "key": rsa_key_hex,
                "streamtype": 1,  # 1=H264
            },
        })

        # Determine sign_code based on encryption level
        sign_code = int(self._encryption_level) if self._encryption_level != P2PEncryptionLevel.NONE else 0

        # Build payload with CMD_SET_PAYLOAD wrapper
        cmd_payload = build_command_payload_json(payload_json, channel=channel, sign_code=sign_code)

        # Encrypt the payload if encryption is active
        if sign_code > 0 and self._p2p_key:
            header = cmd_payload[:10]
            data = cmd_payload[10:]
            encrypted_data = encrypt_p2p(data, self._p2p_key)
            # Update data_len to match encrypted (padded) size
            header = struct.pack("<H", len(encrypted_data)) + header[2:]
            cmd_payload = header + encrypted_data

        result = await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)
        if result is None:
            # Timeout is expected — the HomeBase may not send a result for this
            pass

        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        return True

    async def stop_livestream(self, channel: int = 0) -> None:
        """Stop live video stream."""
        self._is_streaming = False
        payload = build_command_payload_int(0, channel=channel)
        await self.send_command(CommandType.CMD_STOP_REALTIME_MEDIA, payload)

        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()

    # ----- Guard mode -----

    async def set_guard_mode(self, mode: int, user_name: str = "") -> None:
        """Set the station's guard mode via P2P."""
        payload_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_SET_ARMING,
            "mValue3": 0,
            "payload": {
                "mode_type": mode,
                "user_name": user_name,
            },
        })
        cmd_payload = build_command_payload_json(payload_json)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)

    # ----- Alarm trigger -----

    async def trigger_station_alarm(
        self, duration: int = 30, nick_name: str = ""
    ) -> None:
        """Trigger the station alarm siren.

        Uses CMD_SET_PAYLOAD wrapping CMD_SET_TONE_FILE for newer firmware,
        falling back to CMD_SET_TONE_FILE with WithIntString format.
        """
        # Try newer firmware format first (CMD_SET_PAYLOAD wrapping)
        payload_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_SET_TONE_FILE,
            "mValue3": 0,
            "payload": {
                "time_out": duration,
                "user_name": nick_name,
            },
        })
        cmd_payload = build_command_payload_json(payload_json, channel=255)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)

    async def reset_station_alarm(self) -> None:
        """Stop the station alarm siren."""
        await self.trigger_station_alarm(duration=0)

    async def trigger_device_alarm(
        self, duration: int = 30, channel: int = 0
    ) -> None:
        """Trigger a device-specific alarm."""
        from .protocol import build_command_payload_int_string
        payload = build_command_payload_int_string(
            value=duration,
            value_sub=channel,
            str_value=self._admin_user_id,
            channel=channel,
        )
        await self.send_command(CommandType.CMD_SET_DEVS_TONE_FILE, payload)

    async def reset_device_alarm(self, channel: int = 0) -> None:
        """Stop a device-specific alarm."""
        await self.trigger_device_alarm(duration=0, channel=channel)

    # ----- Lock control -----

    async def lock_device(
        self,
        device_channel: int,
        lock: bool = True,
        nick_name: str = "",
        short_user_id: str = "",
    ) -> None:
        """Lock or unlock a WiFi video lock via P2P (plaintext payload variant).

        For WiFi video locks (simplest variant — no per-lock encryption).
        BLE locks and advanced WiFi locks require additional encryption
        which is handled by lock_device_ble() and lock_device_advanced().
        """
        payload_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_P2P_ON_OFF_LOCK,
            "mChannel": device_channel,
            "mValue3": 0,
            "payload": {
                "shortUserId": short_user_id or self._admin_user_id[:8],
                "slOperation": 1 if lock else 0,
                "userId": self._admin_user_id,
                "userName": nick_name,
            },
        })
        cmd_payload = build_command_payload_json(payload_json, channel=device_channel)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)

    async def lock_device_ble(
        self,
        device_channel: int,
        lock: bool = True,
        nick_name: str = "",
        short_user_id: int = 0,
        lock_sequence: int = 0,
    ) -> None:
        """Lock or unlock a BLE lock via P2P with AES-CBC encrypted BLE command."""
        import time as _time

        from ..crypto import (
            encrypt_lock_aes_data,
            encode_lock_payload,
            generate_basic_lock_aes_key,
            get_lock_vector_bytes,
        )

        key = generate_basic_lock_aes_key(self._admin_user_id, self._station_sn)
        iv = get_lock_vector_bytes(self._station_sn)

        # Build ESL BLE command: [0xA1, 0x02, short_user_id(2B BE), 0xA2, 0x01, lock_val,
        #                          0xA3, 0x04, timestamp(4B), 0xA4, len(nick), nick_bytes]
        lock_val = 1 if lock else 0
        ts = int(_time.time())
        nick_bytes = nick_name.encode("utf-8")

        ble_cmd = bytearray()
        ble_cmd += b"\xa1\x02" + struct.pack(">H", short_user_id)
        ble_cmd += b"\xa2\x01" + bytes([lock_val])
        ble_cmd += b"\xa3\x04" + struct.pack(">I", ts)
        ble_cmd += b"\xa4" + bytes([len(nick_bytes)]) + nick_bytes

        import base64 as _b64

        inner_payload = json.dumps({
            "channel": device_channel,
            "lock_cmd": 8,  # ESLBleCommand.ON_OFF_LOCK
            "lock_payload": _b64.b64encode(bytes(ble_cmd)).decode(),
            "seq_num": lock_sequence,
        })

        enc_payload = encrypt_lock_aes_data(key, iv, encode_lock_payload(inner_payload))

        outer_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_DOORLOCK_DATA_PASS_THROUGH,
            "mValue3": 0,
            "payload": {
                "payload": _b64.b64encode(enc_payload).decode(),
            },
        })
        cmd_payload = build_command_payload_json(outer_json, channel=device_channel)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)

    async def lock_device_smart(
        self,
        device_channel: int,
        lock: bool = True,
        nick_name: str = "",
        short_user_id: str = "",
        lock_sequence: int = 0,
    ) -> None:
        """Lock or unlock a smart lock (T8506, T8502, etc.) via P2P."""
        import time as _time

        from ..crypto import (
            encrypt_payload_data,
            generate_smart_lock_aes_key,
            get_lock_vector_bytes,
        )

        timestamp = int(_time.time()) | (int.from_bytes(
            __import__("os").urandom(1), "big"
        ) % 100)
        key = generate_smart_lock_aes_key(self._admin_user_id, timestamp)
        iv = get_lock_vector_bytes(self._station_sn)

        # Build WritePayload: timestamp(4B) + user_id(bytes) + lock_val(1B) + username(bytes) + short_user_id(hex bytes)
        # Note: lock=True -> byte 0, lock=False -> byte 1 (inverted!)
        lock_val = 0 if lock else 1
        ts_bytes = struct.pack(">I", int(_time.time()))
        user_bytes = self._admin_user_id.encode("utf-8")
        nick_bytes = nick_name.encode("utf-8")
        short_bytes = (short_user_id or self._admin_user_id[:8]).encode("utf-8")

        data = ts_bytes + user_bytes + bytes([lock_val]) + nick_bytes + short_bytes
        enc_payload = encrypt_payload_data(data, key, iv)

        import base64 as _b64

        outer_json = json.dumps({
            "account_id": self._admin_user_id,
            "cmd": CommandType.CMD_TRANSFER_PAYLOAD,
            "mChannel": device_channel,
            "mValue3": 0,
            "payload": {
                "apiCommand": 6018,  # SmartLockCommand.ON_OFF_LOCK
                "lock_payload": _b64.b64encode(enc_payload).decode(),
                "seq_num": lock_sequence,
                "time": timestamp,
            },
        })
        cmd_payload = build_command_payload_json(outer_json, channel=device_channel)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, cmd_payload)

    # ----- RTSP control -----

    async def enable_rtsp(self, channel: int = 0, enable: bool = True) -> None:
        """Enable or disable the RTSP stream setting on a camera."""
        from .protocol import build_command_payload_int_string
        payload = build_command_payload_int_string(
            value=1 if enable else 0,
            value_sub=channel,
            str_value=self._admin_user_id,
            channel=channel,
        )
        await self.send_command(CommandType.CMD_NAS_SWITCH, payload)

    async def start_rtsp_stream(self, channel: int = 0) -> None:
        """Start the RTSP stream on a camera. The RTSP URL is returned via event."""
        from .protocol import build_command_payload_int_string
        payload = build_command_payload_int_string(
            value=1,
            value_sub=channel,
            str_value=self._admin_user_id,
            channel=channel,
        )
        await self.send_command(CommandType.CMD_NAS_TEST, payload)

    async def stop_rtsp_stream(self, channel: int = 0) -> None:
        """Stop the RTSP stream on a camera."""
        from .protocol import build_command_payload_int_string
        payload = build_command_payload_int_string(
            value=0,
            value_sub=channel,
            str_value=self._admin_user_id,
            channel=channel,
        )
        await self.send_command(CommandType.CMD_NAS_TEST, payload)

    # ----- Talkback (two-way audio) -----

    async def start_talkback(self, channel: int = 0, use_doorbell_cmd: bool = False) -> None:
        """Start talkback (two-way audio) on a device.

        use_doorbell_cmd: True for indoor/solo/floodlight/wired doorbells
        (uses CMD_DOORBELL_SET_PAYLOAD), False for battery doorbells and
        other devices (uses CMD_START_TALKBACK).
        """
        self._talkback_active = True
        self._video_seq = 0

        if use_doorbell_cmd:
            payload_json = json.dumps({"commandType": 1001})  # CMD_START_SPEAK
            cmd_payload = build_command_payload_json(payload_json, channel=channel)
            await self.send_command(CommandType.CMD_DOORBELL_SET_PAYLOAD, cmd_payload)
        else:
            payload = build_command_payload_int(0, channel=channel)
            await self.send_command(CommandType.CMD_START_TALKBACK, payload)

    async def stop_talkback(self, channel: int = 0, use_doorbell_cmd: bool = False) -> None:
        """Stop talkback."""
        self._talkback_active = False

        if use_doorbell_cmd:
            payload_json = json.dumps({"commandType": 1002})  # CMD_END_SPEAK
            cmd_payload = build_command_payload_json(payload_json, channel=channel)
            await self.send_command(CommandType.CMD_DOORBELL_SET_PAYLOAD, cmd_payload)
        else:
            payload = build_command_payload_int(0, channel=channel)
            await self.send_command(CommandType.CMD_STOP_TALKBACK, payload)

    def send_talkback_audio(self, audio_data: bytes, channel: int = 0) -> None:
        """Send a talkback audio frame to the device.

        audio_data should be raw AAC-encoded audio.
        """
        if not self._connected or not getattr(self, "_talkback_active", False):
            return

        from .protocol import build_talkback_audio_frame

        video_seq = getattr(self, "_video_seq", 0)
        frame = build_talkback_audio_frame(audio_data, video_seq, channel)
        self._video_seq = (video_seq + 1) & 0xFFFF

        # Wrap in DATA envelope
        envelope = (
            struct.pack(">H", len(frame))
            + frame
        )
        pkt = build_udp_packet(P2PMessageType.DATA, envelope)
        self._send_to(pkt)

    # ----- Pan/tilt -----

    async def pan_tilt(self, direction: int) -> None:
        """Pan/tilt a PTZ camera. Direction: 0=up, 1=down, 2=left, 3=right."""
        payload = build_command_payload_int(direction)
        await self.send_command(CommandType.CMD_SET_PAYLOAD, payload)

    # ----- Keepalive -----

    async def _keepalive_loop(self) -> None:
        """Send CMD_PING keepalive for battery-powered devices."""
        while self._connected and self._is_streaming:
            try:
                payload = build_command_void(channel=255)
                seq = self._next_sequence()
                pkt = build_data_message(
                    P2PDataType.DATA, seq, CommandType.CMD_PING, payload,
                )
                self._send_to(pkt)
                await asyncio.sleep(KEEPALIVE_INTERVAL)
            except asyncio.CancelledError:
                return

    @property
    def session_data(self) -> P2PSessionData:
        """Get session data for persistence."""
        return P2PSessionData(
            user_id=self._admin_user_id,
            station_sn=self._station_sn,
            p2p_did=self._p2p_did,
            dsk_key=self._dsk_key,
            encryption_level=self._encryption_level,
            p2p_key=self._p2p_key,
            connect_address=self._connect_address,
            local_address=(self._local_ip, self._local_port),
        )
