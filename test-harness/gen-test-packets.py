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
MINIMUM_PAYLOAD_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-minimum-payload/inject-tap0.jsonl")
ATOMIC_FRAGMENT_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-atomic-fragment/inject-tap0.jsonl")
MAP_ADDRESS_WIDTH_FIXTURE = Path(
    "test-harness/tests/map-address-width/inject-tap0.jsonl")
UNMAPPABLE_QUOTE_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-unmappable/inject-tap0.jsonl")
NONFIRST_FRAGMENT_FIXTURE = Path(
    "test-harness/tests/v4-frag-nonfirst-oob/inject-tap0.jsonl")
FRAGMENT_CHECKSUM_FIXTURE = Path(
    "test-harness/tests/v4-frag-transport-checksum/inject-tap0.jsonl")
MAP_FRAGMENT_TCP_FIXTURE = Path(
    "test-harness/tests/v4-map-frag-tcp/inject-tap0.jsonl")
V6_FRAGMENT_ID_FIXTURE = Path(
    "test-harness/tests/v6-frag-id/inject-tap0.jsonl")
V6_EXTENSION_HEADERS_FIXTURE = Path(
    "test-harness/tests/v6-extension-headers/inject-tap0.jsonl")
V4_DF_FRAGMENTATION_FIXTURE = Path(
    "test-harness/tests/v4-df-fragmentation/inject-tap0.jsonl")
V6_DF_THRESHOLD_FIXTURE = Path(
    "test-harness/tests/v6-df-threshold/inject-tap0.jsonl")


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


def ipv6_transport_checksum(src, dst, protocol, segment):
    pseudoheader = (ipaddress.IPv6Address(src).packed
                    + ipaddress.IPv6Address(dst).packed
                    + struct.pack("!I3xB", len(segment), protocol))
    return checksum(pseudoheader + segment)


def ipv4_transport_checksum(src, dst, protocol, segment):
    pseudoheader = (ipaddress.IPv4Address(src).packed
                    + ipaddress.IPv4Address(dst).packed
                    + struct.pack("!BBH", 0, protocol, len(segment)))
    return checksum(pseudoheader + segment)


def ipv4_tcp_packet(src, dst, sport, dport, payload):
    tcp = bytearray(struct.pack(
        "!HHIIBBHHH", sport, dport, 0, 0, 0x50, 2, 8192, 0, 0))
    pseudoheader = (ipaddress.IPv4Address(src).packed
                    + ipaddress.IPv4Address(dst).packed
                    + struct.pack("!BBH", 0, 6, len(tcp) + len(payload)))
    struct.pack_into("!H", tcp, 16, checksum(pseudoheader + tcp + payload))

    total_length = 20 + len(tcp) + len(payload)
    ipv4 = bytearray(struct.pack(
        "!BBHHHBBH", 0x45, 0, total_length, 1, 0, 255, 6, 0))
    ipv4.extend(ipaddress.IPv4Address(src).packed)
    ipv4.extend(ipaddress.IPv4Address(dst).packed)
    struct.pack_into("!H", ipv4, 10, checksum(ipv4))

    return {
        "timestamp_us": 1000000,
        "layers": [
            {
                "layertype": "ether",
                "dst": "0E:86:3C:CD:51:CA",
                "src": "52:55:0A:00:02:02",
                "etype": 2048,
            },
            {
                "layertype": "Ip",
                "version": 4,
                "ihl": 5,
                "tos": 0,
                "len": total_length,
                "id": 1,
                "flags": {
                    "reserved": False,
                    "dont_fragment": False,
                    "more_fragments": False,
                    "fragment_offset": 0,
                },
                "ttl": 255,
                "proto": 6,
                "chksum": struct.unpack_from("!H", ipv4, 10)[0],
                "src": src,
                "dst": dst,
                "options": [],
            },
            {"layertype": "raw", "data": list(tcp + payload)},
        ],
    }


def ipv4_fragment_packet(src, dst, protocol, identification,
                         fragment_offset, more_fragments, payload,
                         dont_fragment=False):
    total_length = 20 + len(payload)
    fragment_field = (fragment_offset
                      | (0x2000 if more_fragments else 0)
                      | (0x4000 if dont_fragment else 0))
    ipv4 = bytearray(struct.pack(
        "!BBHHHBBH", 0x45, 0, total_length, identification,
        fragment_field, 255, protocol, 0))
    ipv4.extend(ipaddress.IPv4Address(src).packed)
    ipv4.extend(ipaddress.IPv4Address(dst).packed)
    struct.pack_into("!H", ipv4, 10, checksum(ipv4))

    return {
        "timestamp_us": 1000000,
        "layers": [
            {
                "layertype": "ether",
                "dst": "0E:86:3C:CD:51:CA",
                "src": "52:55:0A:00:02:02",
                "etype": 2048,
            },
            {
                "layertype": "Ip",
                "version": 4,
                "ihl": 5,
                "tos": 0,
                "len": total_length,
                "id": identification,
                "flags": {
                    "reserved": False,
                    "dont_fragment": dont_fragment,
                    "more_fragments": more_fragments,
                    "fragment_offset": fragment_offset,
                },
                "ttl": 255,
                "proto": protocol,
                "chksum": struct.unpack_from("!H", ipv4, 10)[0],
                "src": src,
                "dst": dst,
                "options": [],
            },
            {"layertype": "raw", "data": list(payload)},
        ],
    }


def ipv6_atomic_tcp_fragment_packet(identification, dport, timestamp_us):
    tcp = struct.pack(
        "!HHIIBBHHH", 12345, dport, 0, 0, 0x50, 2, 8192, 0, 0)
    fragment = struct.pack("!BBHI", 6, 0, 0, identification)
    return {
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
                "version_class": 0x60000000,
                "payload_length": len(fragment) + len(tcp),
                "next_header": 44,
                "hop_limit": 64,
                "src": REMOTE_V6,
                "dst": LOCAL_V6,
            },
            {"layertype": "raw", "data": list(fragment + tcp)},
        ],
    }


def ipv6_extension_packet(next_header, extension_headers, transport,
                          timestamp_us):
    payload = extension_headers + transport
    return {
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
                "version_class": 0x60000000,
                "payload_length": len(payload),
                "next_header": next_header,
                "hop_limit": 64,
                "src": REMOTE_V6,
                "dst": LOCAL_V6,
            },
            {"layertype": "raw", "data": list(payload)},
        ],
    }


def icmpv6_error_packet(quoted_packet, timestamp_us=1000000,
                        trailing_data=b""):
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
            {"layertype": "raw", "data": list(icmp + trailing_data)},
        ],
    }
    return packet


def write_icmpv6_error_fixture(path, quoted_packet):
    packet = icmpv6_error_packet(quoted_packet)
    path.write_text(json.dumps(packet, separators=(",", ":")) + "\n")


def main():
    map_packet = ipv4_tcp_packet(
        "192.168.1.100", "8.8.8.8", 12345, 81, bytes([42]) * 20)
    MAP_ADDRESS_WIDTH_FIXTURE.write_text(
        json.dumps(map_packet, separators=(",", ":")) + "\n")

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

    packet = icmpv6_error_packet(quoted_packet)
    outer_ip6 = packet["layers"][1]
    outer_payload = packet["layers"][2]["data"]
    atomic_fragment = struct.pack("!BBHI", 58, 0, 0, 0x12345678)
    outer_ip6["payload_length"] += len(atomic_fragment)
    outer_ip6["next_header"] = 44
    packet["layers"][2]["data"] = list(atomic_fragment) + outer_payload
    ATOMIC_FRAGMENT_FIXTURE.write_text(
        json.dumps(packet, separators=(",", ":")) + "\n")

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

    quoted_icmp = bytearray(bytes([128, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]))
    struct.pack_into(
        "!H", quoted_icmp, 2,
        icmpv6_checksum(LOCAL_V6, REMOTE_V6, quoted_icmp))
    quoted_packet = (ipv6_header(len(quoted_icmp), 58,
                                 LOCAL_V6, REMOTE_V6)
                     + quoted_icmp)
    trailing_data = bytes(range(0xa0, 0xb4))
    packet = icmpv6_error_packet(quoted_packet, trailing_data=trailing_data)
    MINIMUM_PAYLOAD_FIXTURE.write_text(
        json.dumps(packet, separators=(",", ":")) + "\n")

    quoted_packet = ipv6_header(
        0, 59, "2001:db8:9999::1", "2001:db8:8888::1")
    write_icmpv6_error_fixture(UNMAPPABLE_QUOTE_FIXTURE, quoted_packet)

    fragment_payload = bytearray(range(24))
    fragment_payload[16:18] = b"\xa5\x5a"
    packet = ipv4_fragment_packet(
        "192.168.1.100", "8.8.8.8", 6, 0x1234, 1, False,
        fragment_payload)
    NONFIRST_FRAGMENT_FIXTURE.write_text(
        json.dumps(packet, separators=(",", ":")) + "\n")

    tcp_payload = bytes(range(0x40, 0x54))
    tcp_segment = bytearray(struct.pack(
        "!HHIIBBHHH", 12345, 81, 0, 0, 0x50, 2, 8192, 0, 0)
        + tcp_payload)
    struct.pack_into(
        "!H", tcp_segment, 16,
        ipv4_transport_checksum(
            "192.168.1.100", "8.8.8.8", 6, tcp_segment))

    udp_payload = bytes(range(0x60, 0x78))
    udp_segment = bytearray(
        struct.pack("!HHHH", 53, 54, 8 + len(udp_payload), 0) + udp_payload)
    struct.pack_into(
        "!H", udp_segment, 6,
        ipv4_transport_checksum(
            "192.168.1.100", "8.8.8.8", 17, udp_segment))

    fragments = (
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 6, 0x3456, 0, True,
            tcp_segment[:24]),
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 6, 0x3456, 3, False,
            tcp_segment[24:]),
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 17, 0x789a, 0, True,
            udp_segment[:16]),
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 17, 0x789a, 2, False,
            udp_segment[16:]),
    )
    for index, fragment in enumerate(fragments):
        fragment["timestamp_us"] += index * 100000
    FRAGMENT_CHECKSUM_FIXTURE.write_text("".join(
        json.dumps(fragment, separators=(",", ":")) + "\n"
        for fragment in fragments))

    map_tcp_payload = bytes([42]) * 20
    map_tcp_segment = bytearray(struct.pack(
        "!HHIIBBHHH", 12345, 81, 0, 0, 0x50, 2, 8192, 0, 0)
        + map_tcp_payload)
    struct.pack_into(
        "!H", map_tcp_segment, 16,
        ipv4_transport_checksum(
            "192.168.1.100", "8.8.8.8", 6, map_tcp_segment))
    map_fragments = (
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 6, 0x4242, 0, True,
            map_tcp_segment[:24]),
        ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 6, 0x4242, 3, False,
            map_tcp_segment[24:]),
    )
    map_fragments[1]["timestamp_us"] += 100000
    MAP_FRAGMENT_TCP_FIXTURE.write_text("".join(
        json.dumps(fragment, separators=(",", ":")) + "\n"
        for fragment in map_fragments))

    v6_fragment_ids = (
        ipv6_atomic_tcp_fragment_packet(0x12345678, 81, 1000000),
        ipv6_atomic_tcp_fragment_packet(0x12349abc, 82, 1100000),
    )
    V6_FRAGMENT_ID_FIXTURE.write_text("".join(
        json.dumps(fragment, separators=(",", ":")) + "\n"
        for fragment in v6_fragment_ids))

    fragmentability_packets = []
    for index, (tcp_length, dport, identification, dont_fragment) in enumerate(
            ((1240, 81, 0x3333, False),
             (1241, 82, 0x4444, False),
             (1241, 83, 0x5555, True))):
        payload = bytes([42]) * (tcp_length - 20)
        tcp = bytearray(struct.pack(
            "!HHIIBBHHH", 12345, dport, 0, 0, 0x50, 2, 8192, 0, 0)
            + payload)
        struct.pack_into(
            "!H", tcp, 16,
            ipv4_transport_checksum(
                "192.168.1.100", "8.8.8.8", 6, tcp))
        packet = ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 6, identification, 0, False,
            tcp, dont_fragment=dont_fragment)
        packet["timestamp_us"] += index * 100000
        fragmentability_packets.append(packet)
    V4_DF_FRAGMENTATION_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in fragmentability_packets))

    def tcp_segment(dport, payload):
        tcp = bytearray(struct.pack(
            "!HHIIBBHHH", 12345, dport, 0, 0, 0x50, 2, 8192, 0, 0)
            + payload)
        struct.pack_into(
            "!H", tcp, 16,
            ipv6_transport_checksum(REMOTE_V6, LOCAL_V6, 6, tcp))
        return bytes(tcp)

    threshold_packets = []
    for index, (tcp_length, dport) in enumerate(((1240, 81), (1241, 82))):
        packet = ipv6_extension_packet(
            6, b"", tcp_segment(dport, bytes([42]) * (tcp_length - 20)),
            1000000 + index * 100000)
        threshold_packets.append(packet)
    V6_DF_THRESHOLD_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in threshold_packets))

    def udp_segment(sport, dport, payload):
        udp = bytearray(struct.pack(
            "!HHHH", sport, dport, 8 + len(payload), 0) + payload)
        struct.pack_into(
            "!H", udp, 6,
            ipv6_transport_checksum(REMOTE_V6, LOCAL_V6, 17, udp))
        return bytes(udp)

    extension_packets = (
        ipv6_extension_packet(
            0, struct.pack("!BB6x", 6, 0),
            tcp_segment(81, bytes([0x41]) * 8), 1000000),
        ipv6_extension_packet(
            43, bytes([60, 1, 0, 0]) + bytes(12)
            + struct.pack("!BB6x", 17, 0),
            udp_segment(53, 54, bytes([0x42]) * 8), 1100000),
        ipv6_extension_packet(
            0, struct.pack("!BB6x", 60, 0)
            + struct.pack("!BB14x", 6, 1),
            tcp_segment(82, bytes([0x43]) * 8), 1200000),
        ipv6_extension_packet(
            44, struct.pack("!BBHI", 60, 0, 0, 0x12345678)
            + struct.pack("!BB6x", 17, 0),
            udp_segment(55, 56, bytes([0x44]) * 8), 1300000),
    )
    V6_EXTENSION_HEADERS_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in extension_packets))


if __name__ == "__main__":
    main()
