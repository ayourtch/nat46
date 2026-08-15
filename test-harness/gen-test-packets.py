#!/usr/bin/env python3
"""Generate deterministic packet fixtures for the NAT46 test harness."""

import ipaddress
import json
from pathlib import Path
import struct


LOCAL_V6 = "2001:db8:1:1::1"
REMOTE_V6 = "2001:4860:4860::8888"
LONG_QUOTE_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-long-length/inject-tap0.jsonl")
SHORT_FRAGMENT_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-short-fragment/inject-tap0.jsonl")
SHORT_TRANSPORT_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-short-transport/inject-tap0.jsonl")


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ipv6_header(payload_len, next_header, src, dst, hop_limit=64):
    return (struct.pack("!IHBB", 0x60000000, payload_len, next_header,
                        hop_limit)
            + ipaddress.IPv6Address(src).packed
            + ipaddress.IPv6Address(dst).packed)


def icmpv6_checksum(src, dst, message):
    pseudoheader = (ipaddress.IPv6Address(src).packed
                    + ipaddress.IPv6Address(dst).packed
                    + struct.pack("!I3xB", len(message), 58))
    return checksum(pseudoheader + message)


def udp_checksum(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    pseudoheader = (ipaddress.IPv6Address(src).packed
                    + ipaddress.IPv6Address(dst).packed
                    + struct.pack("!I3xB", length, 17))
    udp = struct.pack("!HHHH", sport, dport, length, 0) + payload
    return checksum(pseudoheader + udp)


def icmpv6_error_packet(quoted_packet, timestamp_us=1000000):
    icmp = bytearray(bytes([1, 0, 0, 0, 0, 0, 0, 0]) + quoted_packet)
    outer_src = REMOTE_V6
    outer_dst = LOCAL_V6
    struct.pack_into("!H", icmp, 2,
                     icmpv6_checksum(outer_src, outer_dst, icmp))
    packet = {
        "timestamp_us": timestamp_us,
        "layers": [
            {
                "layertype": "ether",
                "dst": "0E:86:3C:CD:51:CA",
                "src": "52:55:0A:00:02:02",
                "etype": 34525,
            },
            {
                "layertype": "Ipv6",
                "version_class": 1610612736,
                "payload_length": len(icmp),
                "next_header": 58,
                "hop_limit": 64,
                "src": outer_src,
                "dst": outer_dst,
            },
            {"layertype": "raw", "data": list(icmp)},
        ],
    }
    return packet


def write_icmpv6_error_fixture(path, quoted_packet):
    packet = icmpv6_error_packet(quoted_packet)
    path.write_text(json.dumps(packet, separators=(",", ":")) + "\n")


def main():
    advertised_payload_len = 1000
    original_payload = bytes([42]) * (advertised_payload_len - 8)
    quoted_checksum = udp_checksum(LOCAL_V6, REMOTE_V6, 53, 54,
                                   original_payload)
    quoted_payload = struct.pack("!HHHH", 53, 54, advertised_payload_len,
                                 quoted_checksum)
    quoted_packet = (ipv6_header(advertised_payload_len, 17,
                                 LOCAL_V6, REMOTE_V6)
                     + quoted_payload)
    write_icmpv6_error_fixture(LONG_QUOTE_FIXTURE, quoted_packet)

    partial_fragment = struct.pack("!BBH", 17, 0, 0)
    quoted_packet = (ipv6_header(8, 44, LOCAL_V6, REMOTE_V6)
                     + partial_fragment)
    write_icmpv6_error_fixture(SHORT_FRAGMENT_FIXTURE, quoted_packet)

    short_transport_cases = (
        ("tcp-empty", 6, 20, 0),
        ("tcp-boundary", 6, 20, 19),
        ("udp-empty", 17, 8, 0),
        ("udp-boundary", 17, 8, 7),
        ("icmp-empty", 58, 8, 0),
        ("icmp-boundary", 58, 8, 7),
    )
    packets = []
    for index, (_name, protocol, required_length, quoted_length) in enumerate(
            short_transport_cases):
        quoted_payload = bytes(range(1, quoted_length + 1))
        quoted_packet = (ipv6_header(required_length, protocol,
                                     LOCAL_V6, REMOTE_V6)
                         + quoted_payload)
        packets.append(icmpv6_error_packet(
            quoted_packet, timestamp_us=1000000 + index * 100000))
    SHORT_TRANSPORT_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))


if __name__ == "__main__":
    main()
