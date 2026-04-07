#!/usr/bin/env python3
"""Compare P2P stream-start packets between our integration and a reference capture.

Usage:
  1. Capture reference traffic from eufy-security-ws addon:
       tcpdump -i any udp -w /tmp/eufy_ref.pcap
     Then trigger a stream start from the addon.

  2. Capture our integration's traffic:
       tcpdump -i any udp -w /tmp/eufy_ours.pcap
     Then trigger a stream start from our integration.

  3. Compare:
       python3 tools/compare_p2p_capture.py /tmp/eufy_ref.pcap /tmp/eufy_ours.pcap

  Or parse a single capture:
       python3 tools/compare_p2p_capture.py /tmp/eufy_ref.pcap

  Or parse our HA log for hex dumps:
       python3 tools/compare_p2p_capture.py --log /tmp/home-assistant.log
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

# --- P2P Protocol Constants ---

MSG_TYPES = {
    0xF120: "LOOKUP_WITH_KEY",
    0xF126: "LOOKUP_WITH_KEY",
    0xF130: "LOCAL_LOOKUP",
    0xF140: "LOOKUP_ADDR",
    0xF141: "CAM_ID",
    0xF142: "CAM_ID_2",
    0xF16A: "LOOKUP_WITH_KEY2",
    0xF182: "LOOKUP_ADDR2",
    0xF183: "CHECK_CAM2",
    0xF1D0: "DATA",
    0xF1D1: "ACK",
    0xF1E0: "PING",
    0xF1E1: "PONG",
    0xF1F0: "END",
}

DATA_TYPES = {
    0xD100: "CONTROL",
    0xD101: "VIDEO",
    0xD102: "AUDIO",
    0xD103: "DATA",
}

CMD_NAMES = {
    0: "CMD_CYCLERECORDING",
    1003: "CMD_START_REALTIME_MEDIA",
    1004: "CMD_STOP_REALTIME_MEDIA",
    1029: "CMD_GATEWAYINFO",
    1139: "CMD_PING",
    1350: "CMD_SET_PAYLOAD",
    1301: "CMD_AUDIO_FRAME",
    1302: "CMD_VIDEO_FRAME",
}

MAGIC_WORD = b"XZYH"


@dataclass
class P2PPacket:
    """A parsed Eufy P2P UDP packet."""

    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    msg_type: int
    payload: bytes
    # Parsed fields (for DATA packets)
    data_type: int | None = None
    sequence: int | None = None
    command_id: int | None = None
    xzyh_raw: bytes | None = None
    cmd_payload: bytes | None = None

    @property
    def msg_type_name(self) -> str:
        return MSG_TYPES.get(self.msg_type, f"0x{self.msg_type:04X}")

    @property
    def data_type_name(self) -> str:
        if self.data_type is None:
            return ""
        return DATA_TYPES.get(self.data_type, f"0x{self.data_type:04X}")

    @property
    def command_name(self) -> str:
        if self.command_id is None:
            return ""
        return CMD_NAMES.get(self.command_id, f"cmd={self.command_id}")

    @property
    def direction(self) -> str:
        # Heuristic: cloud P2P ports are 32100, HomeBase ports vary
        # We send from high ephemeral ports
        if self.src_port > 50000:
            return ">>>"  # outgoing
        return "<<<"  # incoming

    def parse_data(self) -> None:
        """Parse DATA (F1D0) payload into sub-fields."""
        if self.msg_type != 0xF1D0 or len(self.payload) < 4:
            return
        self.data_type = struct.unpack(">H", self.payload[0:2])[0]
        self.sequence = struct.unpack(">H", self.payload[2:4])[0]
        inner = self.payload[4:]
        if len(inner) >= 6 and inner[:4] == MAGIC_WORD:
            self.command_id = struct.unpack("<H", inner[4:6])[0]
            self.xzyh_raw = inner[:16] if len(inner) >= 16 else inner[:6]
            self.cmd_payload = inner[6:] if len(inner) > 6 else b""

    def summary(self) -> str:
        """One-line summary."""
        parts = [
            f"{self.direction} {self.msg_type_name:20s}",
            f"len={len(self.payload):5d}",
        ]
        if self.data_type is not None:
            parts.append(f"dt={self.data_type_name}")
        if self.sequence is not None:
            parts.append(f"seq={self.sequence}")
        if self.command_id is not None:
            parts.append(f"{self.command_name}")
        return " | ".join(parts)

    def detail(self) -> str:
        """Multi-line detail view."""
        lines = [self.summary()]
        lines.append(f"  src={self.src_ip}:{self.src_port} -> dst={self.dst_ip}:{self.dst_port}")
        lines.append(f"  raw ({len(self.payload)} bytes): {self.payload[:64].hex()}")
        if len(self.payload) > 64:
            lines[-1] += "..."

        if self.xzyh_raw and len(self.xzyh_raw) >= 16:
            cmd_id = struct.unpack("<H", self.xzyh_raw[4:6])[0]
            bytes_to_read = struct.unpack("<I", self.xzyh_raw[6:10])[0]
            channel = self.xzyh_raw[12]
            sign_code = self.xzyh_raw[13]
            msg_type = self.xzyh_raw[14]
            lines.append(
                f"  XZYH: cmd={cmd_id} bytes_to_read={bytes_to_read} "
                f"ch={channel} sign={sign_code} type={msg_type}"
            )
            lines.append(f"  XZYH hex: {self.xzyh_raw.hex()}")

        if self.cmd_payload:
            # Show the 10-byte payload header
            if len(self.cmd_payload) >= 10:
                hdr = self.cmd_payload[:10]
                data_len = struct.unpack("<H", hdr[0:2])[0]
                channel = hdr[6]
                sign_code = hdr[7]
                lines.append(
                    f"  payload hdr: data_len={data_len} ch={channel} sign={sign_code} "
                    f"hex={hdr.hex()}"
                )
                body = self.cmd_payload[10:]
                # Try to decode as UTF-8 (JSON)
                try:
                    text = body.decode("utf-8").rstrip("\x00")
                    if text.startswith("{"):
                        lines.append(f"  JSON: {text[:200]}")
                        if len(text) > 200:
                            lines[-1] += "..."
                    else:
                        lines.append(f"  body ({len(body)} bytes): {body[:64].hex()}")
                except UnicodeDecodeError:
                    lines.append(f"  body ({len(body)} bytes): {body[:64].hex()}")
                    if len(body) > 64:
                        lines[-1] += "..."

        return "\n".join(lines)


# --- PCAP Parsing (minimal, no dependencies) ---

def parse_pcap(path: Path) -> list[P2PPacket]:
    """Parse a pcap file and extract UDP packets on Eufy P2P ports."""
    data = path.read_bytes()
    if len(data) < 24:
        print(f"Error: {path} too small for pcap header", file=sys.stderr)
        return []

    # Global header
    magic = struct.unpack("<I", data[0:4])[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    else:
        print(f"Error: {path} is not a valid pcap file (magic=0x{magic:08X})", file=sys.stderr)
        return []

    # version_major, version_minor, thiszone, sigfigs, snaplen, network
    _, _, _, _, snaplen, network = struct.unpack(f"{endian}HHIIII", data[4:24])

    packets: list[P2PPacket] = []
    offset = 24

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        offset += 16

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset : offset + incl_len]
        offset += incl_len

        timestamp = ts_sec + ts_usec / 1_000_000

        # Parse based on link type
        if network == 1:  # Ethernet
            p2p_pkt = _parse_ethernet_udp(pkt_data, timestamp)
        elif network == 0:  # Loopback (BSD)
            p2p_pkt = _parse_loopback_udp(pkt_data, timestamp)
        elif network == 113:  # Linux cooked capture (SLL)
            p2p_pkt = _parse_sll_udp(pkt_data, timestamp)
        elif network == 276:  # Linux cooked capture v2 (SLL2)
            p2p_pkt = _parse_sll2_udp(pkt_data, timestamp)
        else:
            continue

        if p2p_pkt:
            packets.append(p2p_pkt)

    return packets


def _parse_ethernet_udp(data: bytes, ts: float) -> P2PPacket | None:
    """Parse Ethernet -> IP -> UDP -> P2P."""
    if len(data) < 42:  # 14 eth + 20 ip + 8 udp
        return None
    eth_type = struct.unpack(">H", data[12:14])[0]
    if eth_type != 0x0800:  # Not IPv4
        return None
    return _parse_ip_udp(data[14:], ts)


def _parse_loopback_udp(data: bytes, ts: float) -> P2PPacket | None:
    """Parse BSD loopback -> IP -> UDP -> P2P."""
    if len(data) < 32:
        return None
    family = struct.unpack("<I", data[0:4])[0]
    if family != 2:  # AF_INET
        return None
    return _parse_ip_udp(data[4:], ts)


def _parse_sll_udp(data: bytes, ts: float) -> P2PPacket | None:
    """Parse Linux SLL -> IP -> UDP -> P2P."""
    if len(data) < 44:  # 16 sll + 20 ip + 8 udp
        return None
    protocol = struct.unpack(">H", data[14:16])[0]
    if protocol != 0x0800:
        return None
    return _parse_ip_udp(data[16:], ts)


def _parse_sll2_udp(data: bytes, ts: float) -> P2PPacket | None:
    """Parse Linux SLL2 -> IP -> UDP -> P2P."""
    if len(data) < 48:  # 20 sll2 + 20 ip + 8 udp
        return None
    protocol = struct.unpack(">H", data[0:2])[0]
    if protocol != 0x0800:
        return None
    return _parse_ip_udp(data[20:], ts)


def _parse_ip_udp(data: bytes, ts: float) -> P2PPacket | None:
    """Parse IP -> UDP -> P2P packet."""
    if len(data) < 28:  # 20 ip + 8 udp minimum
        return None

    # IP header
    ihl = (data[0] & 0x0F) * 4
    protocol = data[9]
    if protocol != 17:  # Not UDP
        return None

    src_ip = f"{data[12]}.{data[13]}.{data[14]}.{data[15]}"
    dst_ip = f"{data[16]}.{data[17]}.{data[18]}.{data[19]}"

    # UDP header
    udp_offset = ihl
    if len(data) < udp_offset + 8:
        return None
    src_port, dst_port, udp_len = struct.unpack(
        ">HHH", data[udp_offset : udp_offset + 6]
    )

    # UDP payload
    udp_payload = data[udp_offset + 8 : udp_offset + 8 + udp_len - 8]
    if len(udp_payload) < 4:
        return None

    # Parse P2P header
    msg_type = struct.unpack(">H", udp_payload[0:2])[0]
    p2p_len = struct.unpack(">H", udp_payload[2:4])[0]
    p2p_payload = udp_payload[4 : 4 + p2p_len]

    # Filter: only Eufy P2P message types (0xF1xx)
    if (msg_type & 0xFF00) != 0xF100:
        return None

    pkt = P2PPacket(
        timestamp=ts,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        msg_type=msg_type,
        payload=p2p_payload,
    )
    pkt.parse_data()
    return pkt


# --- Log Parsing ---

def parse_ha_log(path: Path) -> list[dict]:
    """Parse hex dumps from our HA log output.

    Looks for lines matching our hex dump format:
      >>> SEND cmd=... / >>> LIVESTREAM BUILD / <<< RECV DATA ...
    """
    text = path.read_text(errors="replace")
    entries = []

    # Match our outgoing hex dumps
    send_pattern = re.compile(
        r">>> SEND cmd=(\d+) \(0x([0-9A-Fa-f]+)\) seq=(\d+) data_type=(\d+)\n"
        r".*?full UDP pkt \((\d+) bytes\): ([0-9a-f]+)",
        re.DOTALL,
    )
    for m in send_pattern.finditer(text):
        entries.append({
            "direction": ">>>",
            "type": "SEND",
            "cmd": int(m.group(1)),
            "cmd_hex": m.group(2),
            "seq": int(m.group(3)),
            "data_type": int(m.group(4)),
            "pkt_len": int(m.group(5)),
            "hex": m.group(6),
        })

    # Match livestream build dumps
    ls_pattern = re.compile(
        r">>> LIVESTREAM BUILD\n"
        r".*?encryption_level=(\S+) sign_code=(\d+)\n"
        r".*?admin_user_id=(\S+)\n"
        r".*?JSON \((\d+) bytes\): (.+?)\n"
        r".*?cmd_payload pre-encrypt \((\d+) bytes\): ([0-9a-f]+)",
        re.DOTALL,
    )
    for m in ls_pattern.finditer(text):
        entries.append({
            "direction": ">>>",
            "type": "LIVESTREAM_BUILD",
            "encryption_level": m.group(1),
            "sign_code": int(m.group(2)),
            "admin_user_id": m.group(3),
            "json_len": int(m.group(4)),
            "json": m.group(5),
            "payload_len": int(m.group(6)),
            "hex": m.group(7),
        })

    # Match incoming data
    recv_pattern = re.compile(
        r"<<< RECV DATA type=(\d+) \(0x([0-9A-Fa-f]+)\) seq=(\d+) data_len=(\d+)\n"
        r".*?raw payload \((\d+) bytes\): ([0-9a-f.]+)",
        re.DOTALL,
    )
    for m in recv_pattern.finditer(text):
        entries.append({
            "direction": "<<<",
            "type": "RECV_DATA",
            "data_type": int(m.group(1)),
            "data_type_hex": m.group(2),
            "seq": int(m.group(3)),
            "data_len": int(m.group(4)),
            "payload_len": int(m.group(5)),
            "hex": m.group(6).replace("...", ""),
        })

    return entries


# --- Comparison ---

def compare_packets(ref: list[P2PPacket], ours: list[P2PPacket]) -> None:
    """Compare two packet sequences, focusing on stream-start commands."""
    print("=" * 80)
    print("REFERENCE CAPTURE")
    print("=" * 80)

    ref_stream = [p for p in ref if p.command_id in (1003, 1350)]
    ours_stream = [p for p in ours if p.command_id in (1003, 1350)]

    print(f"\nTotal packets: {len(ref)} | Stream-related: {len(ref_stream)}")
    print()
    for p in ref:
        print(p.summary())
    print()

    for p in ref_stream:
        print(p.detail())
        print()

    print("=" * 80)
    print("OUR CAPTURE")
    print("=" * 80)
    print(f"\nTotal packets: {len(ours)} | Stream-related: {len(ours_stream)}")
    print()
    for p in ours:
        print(p.summary())
    print()

    for p in ours_stream:
        print(p.detail())
        print()

    # Side-by-side diff of stream commands
    if ref_stream and ours_stream:
        print("=" * 80)
        print("SIDE-BY-SIDE COMPARISON (stream-start commands)")
        print("=" * 80)

        max_pairs = min(len(ref_stream), len(ours_stream))
        for i in range(max_pairs):
            r = ref_stream[i]
            o = ours_stream[i]
            print(f"\n--- Pair {i + 1} ---")
            print(f"REF: {r.command_name} seq={r.sequence}")
            print(f"OUR: {o.command_name} seq={o.sequence}")

            # Compare XZYH headers
            if r.xzyh_raw and o.xzyh_raw:
                if r.xzyh_raw == o.xzyh_raw:
                    print(f"  XZYH: MATCH ({r.xzyh_raw.hex()})")
                else:
                    print(f"  XZYH: DIFFER")
                    print(f"    REF: {r.xzyh_raw.hex()}")
                    print(f"    OUR: {o.xzyh_raw.hex()}")
                    _highlight_diff(r.xzyh_raw, o.xzyh_raw, "    ")

            # Compare payload headers (first 10 bytes after XZYH)
            if r.cmd_payload and o.cmd_payload:
                rh = r.cmd_payload[:10]
                oh = o.cmd_payload[:10]
                if rh == oh:
                    print(f"  Payload hdr: MATCH ({rh.hex()})")
                else:
                    print(f"  Payload hdr: DIFFER")
                    print(f"    REF: {rh.hex()}")
                    print(f"    OUR: {oh.hex()}")
                    _highlight_diff(rh, oh, "    ")

                # Compare payload body
                rb = r.cmd_payload[10:]
                ob = o.cmd_payload[10:]
                if rb == ob:
                    print(f"  Payload body: MATCH ({len(rb)} bytes)")
                else:
                    print(f"  Payload body: DIFFER (ref={len(rb)}B, ours={len(ob)}B)")
                    # Try JSON decode
                    for label, body in [("REF", rb), ("OUR", ob)]:
                        try:
                            text = body.decode("utf-8").rstrip("\x00")
                            if text.startswith("{"):
                                print(f"    {label} JSON: {text[:200]}")
                            else:
                                print(f"    {label} hex: {body[:64].hex()}")
                        except UnicodeDecodeError:
                            print(f"    {label} hex: {body[:64].hex()}")


def _highlight_diff(a: bytes, b: bytes, prefix: str = "") -> None:
    """Show byte-by-byte diff between two byte sequences."""
    max_len = max(len(a), len(b))
    diffs = []
    for i in range(max_len):
        av = a[i] if i < len(a) else None
        bv = b[i] if i < len(b) else None
        if av != bv:
            diffs.append(f"  byte[{i}]: ref=0x{av:02X} ours=0x{bv:02X}" if av is not None and bv is not None
                        else f"  byte[{i}]: ref={'0x%02X' % av if av is not None else 'N/A'} ours={'0x%02X' % bv if bv is not None else 'N/A'}")
    if diffs:
        print(prefix + "DIFFS: " + " | ".join(diffs[:10]))
        if len(diffs) > 10:
            print(prefix + f"  ... and {len(diffs) - 10} more differences")


def print_capture(packets: list[P2PPacket], label: str = "CAPTURE") -> None:
    """Print all packets from a capture."""
    print(f"{'=' * 80}")
    print(f"{label} — {len(packets)} P2P packets")
    print(f"{'=' * 80}")

    # Summary table
    for p in packets:
        print(p.summary())

    # Detail for interesting packets (DATA with commands)
    interesting = [p for p in packets if p.command_id is not None]
    if interesting:
        print(f"\n--- Detailed view ({len(interesting)} command packets) ---\n")
        for p in interesting:
            print(p.detail())
            print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse and compare Eufy P2P packet captures"
    )
    parser.add_argument(
        "pcap_files", nargs="*", type=Path,
        help="PCAP file(s) to parse. If two are given, compare them.",
    )
    parser.add_argument(
        "--log", type=Path,
        help="Parse hex dumps from a Home Assistant log file instead.",
    )
    parser.add_argument(
        "--filter-cmd", type=int, nargs="*",
        help="Only show packets with these command IDs (e.g., 1350 1003)",
    )
    args = parser.parse_args()

    if args.log:
        entries = parse_ha_log(args.log)
        print(f"Parsed {len(entries)} hex dump entries from {args.log}")
        for e in entries:
            print(f"\n{e['direction']} {e['type']}", end="")
            if "cmd" in e:
                cmd_name = CMD_NAMES.get(e["cmd"], f"cmd={e['cmd']}")
                print(f" {cmd_name} seq={e['seq']}", end="")
            print()
            for k, v in e.items():
                if k not in ("direction", "type"):
                    print(f"  {k}: {v}")
        return

    if not args.pcap_files:
        parser.print_help()
        return

    captures = []
    for path in args.pcap_files:
        if not path.exists():
            print(f"Error: {path} not found", file=sys.stderr)
            sys.exit(1)
        pkts = parse_pcap(path)
        if args.filter_cmd:
            pkts = [p for p in pkts if p.command_id in args.filter_cmd]
        captures.append(pkts)

    if len(captures) == 1:
        print_capture(captures[0], str(args.pcap_files[0]))
    elif len(captures) == 2:
        compare_packets(captures[0], captures[1])
    else:
        for i, (path, pkts) in enumerate(zip(args.pcap_files, captures)):
            print_capture(pkts, str(path))
            if i < len(captures) - 1:
                print()


if __name__ == "__main__":
    main()
