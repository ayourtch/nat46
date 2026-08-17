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
SMALL_ATOMIC_QUOTE_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-small-atomic-fragment/inject-tap0.jsonl")
NONATOMIC_QUOTE_FIXTURE = Path(
    "test-harness/tests/ipv6-quote-nonatomic-fragment/inject-tap0.jsonl")
ICMP_PARAMETER_POINTER_FIXTURE = Path(
    "test-harness/tests/icmp-parameter-pointer-order/inject-tap0.jsonl")
ICMP_PARAMETER_POINTER_UNMAPPED_FIXTURE = Path(
    "test-harness/tests/icmp-parameter-pointer-unmapped/inject-tap0.jsonl")
ICMP_PACKET_TOO_BIG_MTU_FIXTURE = Path(
    "test-harness/tests/icmp-packet-too-big-mtu-width/inject-tap0.jsonl")
ICMP_MTU_RESERVED_BITS_FIXTURE = Path(
    "test-harness/tests/icmp-mtu-reserved-bits/inject-tap0.jsonl")
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
UDP_PADDING_FIXTURE = Path(
    "test-harness/tests/v4-udp-padding-checksum/inject-tap0.jsonl")
UDP_PADDING_EXPECTED = Path(
    "test-harness/test-data/expected/v4-udp-padding-checksum.jsonl")
UDP_ZERO_FIXTURE = Path(
    "test-harness/tests/udp-zero-checksum/inject-tap0.jsonl")
UDP_ZERO_EXPECTED = Path(
    "test-harness/test-data/expected/udp-zero-checksum.jsonl")
RFC6052_CANONICAL_FIXTURE = Path(
    "test-harness/tests/rfc6052-canonical/inject-tap0.jsonl")
RFC6052_CANONICAL_EXPECTED = Path(
    "test-harness/test-data/expected/rfc6052-canonical.jsonl")
ICMP_EMBEDDED_FIXTURE = Path(
    "test-harness/tests/icmp-embedded-headers/inject-tap0.jsonl")
ICMP_EMBEDDED_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-embedded-headers.jsonl")
ICMP_QUOTE_LIMIT_FIXTURE = Path(
    "test-harness/tests/icmp-quote-output-limit/inject-tap0.jsonl")
ICMP_QUOTE_LIMIT_REJECTED_FIXTURE = Path(
    "test-harness/tests/icmp-quote-output-limit/inject-rejected-tap0.jsonl")
ICMP_QUOTE_LIMIT_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-quote-output-limit.jsonl")
QUOTED_FRAGMENTED_ICMP_FIXTURE = Path(
    "test-harness/tests/icmp-quote-fragmented-icmp/inject-tap0.jsonl")
QUOTED_FRAGMENTED_ICMP_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-quote-fragmented-icmp.jsonl")
QUOTED_SOURCE_ROUTE_FIXTURE = Path(
    "test-harness/tests/icmp-quote-source-route/inject-tap0.jsonl")
QUOTED_SOURCE_ROUTE_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-quote-source-route.jsonl")
QUOTED_IPV4_PADDING_FIXTURE = Path(
    "test-harness/tests/icmp-quote-ipv4-padding/inject-tap0.jsonl")
QUOTED_IPV4_PADDING_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-quote-ipv4-padding.jsonl")
QUOTED_ICMP_ECHO_CHECKSUM_FIXTURE = Path(
    "test-harness/tests/icmp-quote-echo-checksum/inject-tap0.jsonl")
QUOTED_ICMP_ECHO_CHECKSUM_EXPECTED = Path(
    "test-harness/test-data/expected/icmp-quote-echo-checksum.jsonl")
CONFIG_RANGES_DIR = Path("test-harness/tests/config-ranges")
CONFIG_RANGES_EXPECTED = Path(
    "test-harness/test-data/expected/config-ranges.jsonl")
RFC6052_PREFIX_LENGTHS_DIR = Path(
    "test-harness/tests/rfc6052-prefix-lengths")
RFC6052_PREFIX_LENGTHS_EXPECTED = Path(
    "test-harness/test-data/expected/rfc6052-prefix-lengths.jsonl")
MAP_ZERO_PREFIX_FIXTURE = Path(
    "test-harness/tests/map-zero-prefix/inject-tap0.jsonl")
MAP_ZERO_PREFIX_EXPECTED = Path(
    "test-harness/test-data/expected/map-zero-prefix.jsonl")
MAP_ZERO_PREFIX_CONFIG_EXPECTED = Path(
    "test-harness/test-data/expected/map-zero-prefix-config.txt")
REMOVE_SEMANTIC_RULE_DIR = Path(
    "test-harness/tests/remove-semantic-rule")
REMOVE_SEMANTIC_RULE_EXPECTED = Path(
    "test-harness/test-data/expected/remove-semantic-rule.jsonl")
REMOVE_SEMANTIC_RULE_CONFIG_EXPECTED = Path(
    "test-harness/test-data/expected/remove-semantic-rule-config.txt")


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


def generate_quoted_fragmented_icmp():
    def echo_request(identifier, sequence, marker):
        message = bytearray(
            struct.pack("!BBHHH", 8, 0, 0, identifier, sequence) + marker)
        struct.pack_into("!H", message, 2, checksum(message))
        assert checksum(message) == 0
        return bytes(message)

    first_message = echo_request(0x1911, 0x0101, b"FIRST19!")
    first_quote = (ipv4_header(
        "8.8.8.8", "192.168.1.100", 1, len(first_message),
        identification=0x19f1, more_fragments=True)
                   + first_message[:4])
    nonfirst_quote = (ipv4_header(
        "8.8.8.8", "192.168.1.100", 1, 8,
        identification=0x19f2, fragment_offset=1)
                      + b"NFRAG19!")
    control_message = echo_request(0x1919, 0x0102, b"CTRL19!!")
    control_quote = (ipv4_header(
        "8.8.8.8", "192.168.1.100", 1, len(control_message),
        identification=0x19f3)
                     + control_message)

    cases = (
        (first_quote, 0x29f1, 3, 1000000),
        (nonfirst_quote, 0x29f2, 3, 1100000),
        (control_quote, 0x29f3, 1, 1200000),
    )
    packets = []
    checks = []
    for quote, outer_identification, outer_code, timestamp_us in cases:
        packet = icmpv4_error_packet(
            quote, timestamp_us, outer_identification, code=outer_code)
        message = bytes(packet["layers"][2]["data"])
        assert checksum(message) == 0
        packets.append(packet)
        checks.append({
            "count": 1,
            "packet": {
                "direction": "tx",
                "layers": [
                    {
                        "layertype": "Ip",
                        "id": outer_identification,
                        "proto": 1,
                        "src": "192.168.1.100",
                        "dst": "8.8.8.8",
                    },
                    {"layertype": "Icmp", "typ": 3, "code": outer_code},
                    {"layertype": "raw", "data": list(message[4:])},
                ],
            },
        })

    checks.append({
        "count": 1,
        "packet": {
            "direction": "rx",
            "layers": [
                {
                    "layertype": "Ipv6",
                    "src": LOCAL_V6,
                    "dst": REMOTE_V6,
                    "next_header": 58,
                },
                {"layertype": "Icmpv6", "code": 0},
            ],
        },
    })

    QUOTED_FRAGMENTED_ICMP_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))
    QUOTED_FRAGMENTED_ICMP_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 1,
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def generate_quoted_source_routes():
    cases = (
        (0x83, 4, "203.0.113.11", 0x2a01, 0x3a01, 3, 41001, 42001,
         b"LSR-ACT!", 1000000, True),
        (0x89, 4, "198.51.100.22", 0x2a02, 0x3a02, 3, 41002, 42002,
         b"SSR-ACT!", 1100000, True),
        (0x83, 8, "203.0.113.33", 0x2a03, 0x3a03, 1, 41003, 42003,
         b"LSR-DONE", 1200000, False),
        (0x89, 8, "198.51.100.44", 0x2a04, 0x3a04, 0, 41004, 42004,
         b"SSR-DONE", 1300000, False),
    )
    packets = []
    checks = []

    for (option_type, pointer, route_address, inner_identification,
         outer_identification, outer_code, sport, dport, marker,
         timestamp_us, active) in cases:
        options = (struct.pack(
            "!BBB4s", option_type, 7, pointer,
            ipaddress.IPv4Address(route_address).packed)
                   + b"\0")
        assert len(options) == 8
        assert options[1] == 7
        assert options[2] == pointer

        source_segment = transport_segment(
            "8.8.8.8", "192.168.1.100", 17, sport, dport, marker)
        quoted_ipv4 = (ipv4_header(
            "8.8.8.8", "192.168.1.100", 17, len(source_segment),
            identification=inner_identification, options=options)
                       + source_segment)
        inner_ihl = (quoted_ipv4[0] & 0x0f) * 4
        assert inner_ihl == 28
        assert struct.unpack_from("!H", quoted_ipv4, 2)[0] == len(quoted_ipv4)
        assert checksum(quoted_ipv4[:inner_ihl]) == 0

        packet = icmpv4_error_packet(
            quoted_ipv4, timestamp_us, outer_identification, code=outer_code)
        source_message = bytes(packet["layers"][2]["data"])
        assert checksum(source_message) == 0
        packets.append(packet)
        checks.append({
            "count": 1,
            "packet": {
                "direction": "tx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip",
                        "id": outer_identification,
                        "proto": 1,
                        "src": "192.168.1.100",
                        "dst": "8.8.8.8",
                    },
                    {"layertype": "Icmp", "typ": 3, "code": outer_code},
                    {"layertype": "raw", "data": list(source_message[4:])},
                ],
            },
        })

        translated_segment = transport_segment(
            REMOTE_V6, LOCAL_V6, 17, sport, dport, marker)
        translated_quote = (ipv6_header(
            len(translated_segment), 17, REMOTE_V6, LOCAL_V6,
            hop_limit=47)
                            + translated_segment)
        translated_code = 4 if outer_code == 3 else 0
        translated_icmp = bytearray(
            struct.pack("!BBHI", 1, translated_code, 0, 0)
            + translated_quote)
        translated_checksum = icmpv6_checksum(
            LOCAL_V6, REMOTE_V6, translated_icmp)
        struct.pack_into("!H", translated_icmp, 2, translated_checksum)
        assert icmpv6_checksum(LOCAL_V6, REMOTE_V6, translated_icmp) == 0
        checks.append({
            "count": 0 if active else 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(translated_icmp),
                        "next_header": 58,
                        "hop_limit": 254,
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Icmpv6",
                        "type_": 1,
                        "code": translated_code,
                        "checksum": translated_checksum,
                    },
                    {
                        "layertype": "icmpv6DestUnreach",
                        "unused": 0,
                        "invoking_packet": list(translated_quote),
                    },
                ],
            },
        })

    QUOTED_SOURCE_ROUTE_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))
    QUOTED_SOURCE_ROUTE_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 2,
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def generate_quoted_ipv4_padding():
    padded_marker = b"PADDED-DATAGRAM!"
    padding = b"LINKPAD-P21!"
    truncated_marker = b"TRUNCATED-CTRL!!"
    assert len(padded_marker) == len(truncated_marker) == 16
    assert len(padding) == 12

    padded_source = transport_segment(
        "8.8.8.8", "192.168.1.100", 17, 43001, 44001,
        padded_marker)
    padded_inner = (ipv4_header(
        "8.8.8.8", "192.168.1.100", 17, len(padded_source),
        identification=0x3b01)
                    + padded_source)
    padded_quote = padded_inner + padding

    truncated_source = transport_segment(
        "8.8.8.8", "192.168.1.100", 17, 43002, 44002,
        truncated_marker)
    truncated_header = ipv4_header(
        "8.8.8.8", "192.168.1.100", 17, len(truncated_source),
        identification=0x3b02)
    truncated_transport_len = 12
    truncated_quote = (
        truncated_header + truncated_source[:truncated_transport_len])

    assert len(padded_inner) == len(truncated_header) + len(truncated_source)
    assert len(padded_inner) == 44
    assert len(padded_quote) == 56
    assert len(truncated_quote) == 32
    assert struct.unpack_from("!H", padded_inner, 2)[0] == 44
    assert struct.unpack_from("!H", truncated_header, 2)[0] == 44
    assert checksum(padded_inner[:20]) == 0
    assert checksum(truncated_header) == 0

    cases = (
        (padded_quote, padded_source, padded_marker, padding,
         0x4b01, 3, 43001, 44001, 1000000),
        (truncated_quote, truncated_source, truncated_marker, b"",
         0x4b02, 1, 43002, 44002, 1100000),
    )
    packets = []
    checks = []

    def translated_check(invoking_packet, translated_code, count):
        translated_icmp = bytearray(
            struct.pack("!BBHI", 1, translated_code, 0, 0)
            + invoking_packet)
        translated_checksum = icmpv6_checksum(
            LOCAL_V6, REMOTE_V6, translated_icmp)
        struct.pack_into("!H", translated_icmp, 2, translated_checksum)
        assert icmpv6_checksum(LOCAL_V6, REMOTE_V6, translated_icmp) == 0
        return {
            "count": count,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(translated_icmp),
                        "next_header": 58,
                        "hop_limit": 254,
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Icmpv6",
                        "type_": 1,
                        "code": translated_code,
                        "checksum": translated_checksum,
                    },
                    {
                        "layertype": "icmpv6DestUnreach",
                        "unused": 0,
                        "invoking_packet": list(invoking_packet),
                    },
                ],
            },
        }

    for (source_quote, full_source, marker, trailing_padding,
         outer_identification, outer_code, sport, dport,
         timestamp_us) in cases:
        packet = icmpv4_error_packet(
            source_quote, timestamp_us, outer_identification,
            code=outer_code)
        source_message = bytes(packet["layers"][2]["data"])
        assert checksum(source_message) == 0
        packets.append(packet)
        checks.append({
            "count": 1,
            "packet": {
                "direction": "tx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip",
                        "id": outer_identification,
                        "proto": 1,
                        "src": "192.168.1.100",
                        "dst": "8.8.8.8",
                    },
                    {"layertype": "Icmp", "typ": 3, "code": outer_code},
                    {"layertype": "raw", "data": list(source_message[4:])},
                ],
            },
        })

        translated_full = transport_segment(
            REMOTE_V6, LOCAL_V6, 17, sport, dport, marker)
        visible_transport_len = len(source_quote) - 20 - len(trailing_padding)
        translated_quote = (ipv6_header(
            len(full_source), 17, REMOTE_V6, LOCAL_V6, hop_limit=47)
                            + translated_full[:visible_transport_len])
        translated_code = 4 if outer_code == 3 else 0
        checks.append(translated_check(translated_quote, translated_code, 1))
        if trailing_padding:
            checks.append(translated_check(
                translated_quote + trailing_padding, translated_code, 0))

    QUOTED_IPV4_PADDING_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))
    QUOTED_IPV4_PADDING_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 2,
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def checksum_update(checksum_value, old_value, new_value):
    total = ((~checksum_value & 0xffff)
             + (~old_value & 0xffff) + new_value)
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def generate_quoted_icmp_echo_checksums():
    def source_echo(icmp_type, identifier, sequence, marker):
        echo = bytearray(
            struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence)
            + marker)
        struct.pack_into(
            "!H", echo, 2,
            icmpv6_checksum(LOCAL_V6, REMOTE_V6, echo))
        assert icmpv6_checksum(LOCAL_V6, REMOTE_V6, echo) == 0
        return bytes(echo)

    def translated_echo(icmp_type, identifier, sequence, marker):
        echo = bytearray(
            struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence)
            + marker)
        struct.pack_into("!H", echo, 2, checksum(echo))
        assert checksum(echo) == 0
        return bytes(echo)

    cases = (
        {
            "timestamp_us": 1000000,
            "outer_version_class": 0x60002101,
            "outer_type": 3,
            "outer_code": 0,
            "output_type": 11,
            "output_code": 0,
            "fragment_id": None,
            "inner_type": 128,
            "translated_inner_type": 8,
            "echo_id": 0xe211,
            "echo_sequence": 0x0101,
            "marker": b"ECHO-ORDINARY-21",
        },
        {
            "timestamp_us": 1100000,
            "outer_version_class": 0x60002102,
            "outer_type": 1,
            "outer_code": 4,
            "output_type": 3,
            "output_code": 3,
            "fragment_id": 0x21a7e222,
            "inner_type": 129,
            "translated_inner_type": 0,
            "echo_id": 0xe212,
            "echo_sequence": 0x0202,
            "marker": b"ECHO-ATOMIC-0022",
        },
    )
    packets = []
    checks = []
    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }

    for case in cases:
        source_inner_echo = source_echo(
            case["inner_type"], case["echo_id"],
            case["echo_sequence"], case["marker"])
        assert len(source_inner_echo) == 24
        source_quote = (ipv6_header(
            len(source_inner_echo), 58, LOCAL_V6, REMOTE_V6,
            hop_limit=47)
                        + source_inner_echo)
        assert len(source_quote) == 64
        packet = icmpv6_error_packet(
            source_quote, case["timestamp_us"],
            icmp_type=case["outer_type"],
            icmp_code=case["outer_code"])
        packet["layers"][1]["version_class"] = case["outer_version_class"]
        source_outer_icmp = bytes(packet["layers"][2]["data"])
        assert len(source_outer_icmp) == 72
        assert icmpv6_checksum(
            REMOTE_V6, LOCAL_V6, source_outer_icmp) == 0

        if case["fragment_id"] is None:
            source_layers = [
                {
                    "layertype": "Ipv6",
                    "version_class": case["outer_version_class"],
                    "payload_length": len(source_outer_icmp),
                    "next_header": 58,
                    "hop_limit": 63,
                    "src": REMOTE_V6,
                    "dst": LOCAL_V6,
                },
                {
                    "layertype": "Icmpv6",
                    "type_": case["outer_type"],
                    "code": case["outer_code"],
                    "checksum": struct.unpack_from(
                        "!H", source_outer_icmp, 2)[0],
                },
                {
                    "layertype": "icmpv6TimeExceeded",
                    "unused": 0,
                    "invoking_packet": list(source_quote),
                },
            ]
        else:
            outer_fragment = struct.pack(
                "!BBHI", 58, 0, 0, case["fragment_id"])
            packet["layers"][1]["payload_length"] += len(outer_fragment)
            packet["layers"][1]["next_header"] = 44
            packet["layers"][2]["data"] = list(
                outer_fragment + source_outer_icmp)
            source_layers = [
                {
                    "layertype": "Ipv6",
                    "version_class": case["outer_version_class"],
                    "payload_length": len(outer_fragment)
                                      + len(source_outer_icmp),
                    "next_header": 44,
                    "hop_limit": 63,
                    "src": REMOTE_V6,
                    "dst": LOCAL_V6,
                },
                {
                    "layertype": "raw",
                    "data": list(outer_fragment + source_outer_icmp),
                },
            ]

        packets.append(packet)
        checks.append({
            "count": 1,
            "packet": {
                "direction": "tx",
                "valid_checksums": True,
                "valid_quoted_icmp_checksum": True,
                "layers": source_layers,
            },
        })

        output_inner_echo = translated_echo(
            case["translated_inner_type"], case["echo_id"],
            case["echo_sequence"], case["marker"])
        output_inner_ipv4 = (ipv4_header(
            "192.168.1.100", "8.8.8.8", 1, len(output_inner_echo),
            identification=0, ttl=47)
                             + output_inner_echo)
        assert len(output_inner_ipv4) == 44
        output_outer_icmp = bytearray(struct.pack(
            "!BBHI", case["output_type"], case["output_code"], 0, 0)
                                      + output_inner_ipv4)
        correct_outer_checksum = checksum(output_outer_icmp)
        struct.pack_into(
            "!H", output_outer_icmp, 2, correct_outer_checksum)
        assert checksum(output_outer_icmp) == 0

        pre_type_echo = bytearray(source_inner_echo)
        struct.pack_into("!H", pre_type_echo, 2, 0)
        pre_type_checksum = checksum(pre_type_echo)
        final_inner_checksum = struct.unpack_from(
            "!H", output_inner_echo, 2)[0]
        buggy_outer_checksum = checksum_update(
            correct_outer_checksum, pre_type_checksum,
            final_inner_checksum)
        buggy_outer_icmp = bytearray(output_outer_icmp)
        struct.pack_into("!H", buggy_outer_icmp, 2, buggy_outer_checksum)
        assert buggy_outer_checksum != correct_outer_checksum
        assert checksum(buggy_outer_icmp) != 0

        output_ip = {
            "layertype": "Ip",
            "version": 4,
            "ihl": 5,
            "tos": 0,
            "len": 20 + len(output_outer_icmp),
            "flags": unfragmented_flags,
            "ttl": 63,
            "proto": 1,
            "src": "8.8.8.8",
            "dst": "192.168.1.100",
            "options": [],
        }
        if case["fragment_id"] is not None:
            output_ip["id"] = case["fragment_id"] & 0xffff

        def output_check(checksum_value, count, validate_checksums):
            return {
                "count": count,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": validate_checksums,
                    "valid_quoted_icmp_checksum": validate_checksums,
                    "layers": [
                        output_ip,
                        {
                            "layertype": "Icmp",
                            "typ": case["output_type"],
                            "code": case["output_code"],
                            "chksum": checksum_value,
                        },
                        {
                            "layertype": "raw",
                            "data": list(output_outer_icmp[4:]),
                        },
                    ],
                },
            }

        checks.append(output_check(correct_outer_checksum, 1, True))
        checks.append(output_check(buggy_outer_checksum, 0, False))

    QUOTED_ICMP_ECHO_CHECKSUM_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))
    QUOTED_ICMP_ECHO_CHECKSUM_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 2,
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def transport_segment(src, dst, protocol, sport, dport, payload):
    if protocol == 6:
        segment = bytearray(struct.pack(
            "!HHIIBBHHH", sport, dport, 0x10203040, 0, 0x50, 2,
            16384, 0, 0) + payload)
        checksum_offset = 16
    elif protocol == 17:
        segment = bytearray(struct.pack(
            "!HHHH", sport, dport, 8 + len(payload), 0) + payload)
        checksum_offset = 6
    else:
        raise ValueError(f"unsupported transport protocol {protocol}")

    checksum_fn = (ipv4_transport_checksum
                   if ipaddress.ip_address(src).version == 4
                   else ipv6_transport_checksum)
    struct.pack_into(
        "!H", segment, checksum_offset,
        checksum_fn(src, dst, protocol, segment))
    assert checksum_fn(src, dst, protocol, segment) == 0
    return bytes(segment)


def ipv4_header(src, dst, protocol, payload_len, identification=0,
                ttl=47, fragment_offset=0, more_fragments=False,
                options=b""):
    assert len(options) % 4 == 0
    assert len(options) <= 40
    header_len = 20 + len(options)
    fragment_field = (fragment_offset
                      | (0x2000 if more_fragments else 0))
    header = bytearray(struct.pack(
        "!BBHHHBBH", 0x40 | (header_len // 4), 0,
        header_len + payload_len, identification,
        fragment_field, ttl, protocol, 0))
    header.extend(ipaddress.IPv4Address(src).packed)
    header.extend(ipaddress.IPv4Address(dst).packed)
    header.extend(options)
    struct.pack_into("!H", header, 10, checksum(header))
    assert checksum(header) == 0
    return bytes(header)


def icmpv4_error_packet(quoted_packet, timestamp_us, identification,
                        code=3, field=0, trailing_data=b""):
    message = bytearray(
        struct.pack("!BBHI", 3, code, 0, field)
        + quoted_packet + trailing_data)
    struct.pack_into("!H", message, 2, checksum(bytes(message)))
    packet = ipv4_fragment_packet(
        "192.168.1.100", "8.8.8.8", 1, identification, 0, False,
        message)
    packet["timestamp_us"] = timestamp_us
    return packet


def rfc4884_extension(c_type, marker):
    assert len(marker) == 4
    extension = bytearray(
        struct.pack("!BBH", 0x20, 0, 0)
        + struct.pack("!HBB", 8, 0xf7, c_type)
        + marker)
    struct.pack_into("!H", extension, 2, checksum(extension))
    assert len(extension) == 12
    assert checksum(extension) == 0
    return bytes(extension)


def generate_icmp_embedded_headers():
    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }
    cases = (
        (6, 443, 40000, b"quoted-v4-tcp!"),
        (17, 53, 53000, b"quoted-v4-udp!"),
    )
    packets = []
    checks = []

    # The ICMPv4 error travels local-to-remote and quotes the earlier
    # remote-to-local packet, so its embedded lookup reverses the outer rules.
    for index, (protocol, sport, dport, payload) in enumerate(cases):
        source_segment = transport_segment(
            "8.8.8.8", "192.168.1.100", protocol, sport, dport, payload)
        quoted_ipv4 = (ipv4_header(
            "8.8.8.8", "192.168.1.100", protocol, len(source_segment),
            identification=0x4100 + index)
                       + source_segment)
        packets.append(icmpv4_error_packet(
            quoted_ipv4, 1000000 + index * 100000, 0x5100 + index))

        translated_segment = transport_segment(
            REMOTE_V6, LOCAL_V6, protocol, sport, dport, payload)
        translated_quote = (ipv6_header(
            len(translated_segment), protocol, REMOTE_V6, LOCAL_V6,
            hop_limit=47)
                            + translated_segment)
        translated_icmp = bytearray(
            struct.pack("!BBHI", 1, 4, 0, 0) + translated_quote)
        translated_checksum = icmpv6_checksum(
            LOCAL_V6, REMOTE_V6, translated_icmp)
        struct.pack_into("!H", translated_icmp, 2, translated_checksum)
        assert icmpv6_checksum(LOCAL_V6, REMOTE_V6, translated_icmp) == 0

        checks.append({
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(translated_icmp),
                        "next_header": 58,
                        "hop_limit": 254,
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Icmpv6",
                        "type_": 1,
                        "code": 4,
                        "checksum": translated_checksum,
                    },
                    {
                        "layertype": "icmpv6DestUnreach",
                        "unused": 0,
                        "invoking_packet": list(translated_quote),
                    },
                ],
            },
        })

    # The ICMPv6 error travels remote-to-local and quotes the earlier
    # local-to-remote packet, again requiring the reverse outer-rule direction.
    for index, (protocol, sport, dport, payload) in enumerate((
            (6, 40001, 443, b"quoted-v6-tcp!"),
            (17, 53001, 53, b"quoted-v6-udp!"))):
        source_segment = transport_segment(
            LOCAL_V6, REMOTE_V6, protocol, sport, dport, payload)
        quoted_ipv6 = (ipv6_header(
            len(source_segment), protocol, LOCAL_V6, REMOTE_V6,
            hop_limit=47)
                       + source_segment)
        packets.append(icmpv6_error_packet(
            quoted_ipv6, timestamp_us=1200000 + index * 100000,
            icmp_type=1, icmp_code=4))

        translated_segment = transport_segment(
            "192.168.1.100", "8.8.8.8", protocol, sport, dport, payload)
        translated_quote = (ipv4_header(
            "192.168.1.100", "8.8.8.8", protocol,
            len(translated_segment), ttl=47)
                            + translated_segment)
        translated_icmp = bytearray(
            struct.pack("!BBHI", 3, 3, 0, 0) + translated_quote)
        translated_checksum = checksum(translated_icmp)
        struct.pack_into("!H", translated_icmp, 2, translated_checksum)
        assert checksum(translated_icmp) == 0

        checks.append({
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip",
                        "version": 4,
                        "ihl": 5,
                        "tos": 0,
                        "len": 20 + len(translated_icmp),
                        "flags": unfragmented_flags,
                        "ttl": 63,
                        "proto": 1,
                        "src": "8.8.8.8",
                        "dst": "192.168.1.100",
                        "options": [],
                    },
                    {
                        "layertype": "Icmp",
                        "typ": 3,
                        "code": 3,
                        "chksum": translated_checksum,
                    },
                    {
                        "layertype": "raw",
                        "data": list(b"\0\0\0\0" + translated_quote),
                    },
                ],
            },
        })

    # RFC 4884 gives both extensible directions an explicit 128-byte quote.
    # Translating the IPv4 header grows the first quote to 148 bytes, which is
    # padded to 152 before its recognizable extension. The reverse direction
    # shrinks the packet to 108 bytes and pads it back to the 128-byte minimum.
    v4_payload = b"RFC4884-V4-QUOTE:" + bytes(range(83))
    v4_source_segment = transport_segment(
        "8.8.8.8", "192.168.1.100", 17, 33434, 45000, v4_payload)
    v4_quote = (ipv4_header(
        "8.8.8.8", "192.168.1.100", 17, len(v4_source_segment),
        identification=0x4884)
                + v4_source_segment)
    v4_extension = rfc4884_extension(1, b"V4X!")
    packets.append(icmpv4_error_packet(
        v4_quote, 1400000, 0x5884, field=32 << 16,
        trailing_data=v4_extension))

    v4_translated_segment = transport_segment(
        REMOTE_V6, LOCAL_V6, 17, 33434, 45000, v4_payload)
    v6_padded_quote = (ipv6_header(
        len(v4_translated_segment), 17, REMOTE_V6, LOCAL_V6, hop_limit=47)
                       + v4_translated_segment + bytes(4))
    v4_to_v6_field = 19 << 24
    v4_to_v6_icmp = bytearray(
        struct.pack("!BBHI", 1, 4, 0, v4_to_v6_field)
        + v6_padded_quote + v4_extension)
    v4_to_v6_checksum = icmpv6_checksum(
        LOCAL_V6, REMOTE_V6, v4_to_v6_icmp)
    struct.pack_into("!H", v4_to_v6_icmp, 2, v4_to_v6_checksum)

    assert len(v4_quote) == 128
    assert len(v6_padded_quote) == 152
    assert v4_to_v6_icmp[4] == 19
    assert v4_to_v6_icmp[8 + 152:] == v4_extension
    assert icmpv6_checksum(
        LOCAL_V6, REMOTE_V6, v4_to_v6_icmp) == 0
    checks.extend((
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "payload_length": len(v4_to_v6_icmp),
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Icmpv6",
                        "type_": 1,
                        "code": 4,
                    },
                    {
                        "layertype": "icmpv6DestUnreach",
                        "unused": v4_to_v6_field,
                    },
                ],
            },
        },
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(v4_to_v6_icmp),
                        "next_header": 58,
                        "hop_limit": 254,
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Icmpv6",
                        "type_": 1,
                        "code": 4,
                        "checksum": v4_to_v6_checksum,
                    },
                    {
                        "layertype": "icmpv6DestUnreach",
                        "invoking_packet": list(
                            v6_padded_quote + v4_extension),
                    },
                ],
            },
        },
    ))

    v6_payload = b"RFC4884-V6-QUOTE:" + bytes(range(63))
    v6_source_segment = transport_segment(
        LOCAL_V6, REMOTE_V6, 17, 45001, 33435, v6_payload)
    v6_quote = (ipv6_header(
        len(v6_source_segment), 17, LOCAL_V6, REMOTE_V6, hop_limit=47)
                + v6_source_segment)
    v6_extension = rfc4884_extension(2, b"V6X!")
    packets.append(icmpv6_error_packet(
        v6_quote + v6_extension, timestamp_us=1500000,
        icmp_type=3, icmp_code=0, field=16 << 24))

    v6_translated_segment = transport_segment(
        "192.168.1.100", "8.8.8.8", 17, 45001, 33435, v6_payload)
    v4_padded_quote = (ipv4_header(
        "192.168.1.100", "8.8.8.8", 17, len(v6_translated_segment),
        ttl=47)
                       + v6_translated_segment + bytes(20))
    v6_to_v4_field = 32 << 16
    v6_to_v4_icmp = bytearray(
        struct.pack("!BBHI", 11, 0, 0, v6_to_v4_field)
        + v4_padded_quote + v6_extension)
    v6_to_v4_checksum = checksum(v6_to_v4_icmp)
    struct.pack_into("!H", v6_to_v4_icmp, 2, v6_to_v4_checksum)

    assert len(v6_quote) == 128
    assert len(v4_padded_quote) == 128
    assert v6_to_v4_icmp[5] == 32
    assert v6_to_v4_icmp[8 + 128:] == v6_extension
    assert checksum(v6_to_v4_icmp) == 0
    checks.extend((
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "layers": [
                    {
                        "layertype": "Ip",
                        "len": 20 + len(v6_to_v4_icmp),
                        "src": "8.8.8.8",
                        "dst": "192.168.1.100",
                    },
                    {
                        "layertype": "Icmp",
                        "typ": 11,
                        "code": 0,
                    },
                    {
                        "layertype": "raw",
                        "data_prefix": list(struct.pack(
                            "!I", v6_to_v4_field)),
                    },
                ],
            },
        },
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip",
                        "version": 4,
                        "ihl": 5,
                        "tos": 0,
                        "len": 20 + len(v6_to_v4_icmp),
                        "flags": unfragmented_flags,
                        "ttl": 63,
                        "proto": 1,
                        "src": "8.8.8.8",
                        "dst": "192.168.1.100",
                        "options": [],
                    },
                    {
                        "layertype": "Icmp",
                        "typ": 11,
                        "code": 0,
                        "chksum": v6_to_v4_checksum,
                    },
                    {
                        "layertype": "raw",
                        "data": list(
                            struct.pack("!I", v6_to_v4_field)
                            + v4_padded_quote + v6_extension),
                    },
                ],
            },
        },
    ))

    ICMP_EMBEDDED_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packets))
    ICMP_EMBEDDED_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 6,
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def generate_icmp_quote_output_limit():
    accepted_quote_len = 65499
    rejected_quote_len = accepted_quote_len + 1
    fragment_offset = 1

    def quoted_fragment(quote_len, marker, identification):
        payload = marker + bytes([0xa5]) * (quote_len - 20 - len(marker))
        return (ipv4_header(
            "8.8.8.8", "192.168.1.100", 6, len(payload),
            identification=identification, fragment_offset=fragment_offset)
                + payload)

    accepted_quote = quoted_fragment(
        accepted_quote_len, b"QUOTE-LIMIT-ACCEPTED:", 0x6100)
    rejected_quote = quoted_fragment(
        rejected_quote_len, b"QUOTE-LIMIT-REJECTED:", 0x6101)
    packets = [
        icmpv4_error_packet(
            accepted_quote, 1000000, 0x7100),
        icmpv4_error_packet(
            rejected_quote, 1100000, 0x7101),
    ]

    accepted_inner_payload = accepted_quote[20:]
    fragment_header = struct.pack(
        "!BBHI", 6, 0, fragment_offset << 3, 0x6100)
    translated_quote = (ipv6_header(
        len(fragment_header) + len(accepted_inner_payload), 44,
        REMOTE_V6, LOCAL_V6, hop_limit=47)
                        + fragment_header + accepted_inner_payload)
    translated_icmp = bytearray(
        struct.pack("!BBHI", 1, 4, 0, 0) + translated_quote)
    translated_checksum = icmpv6_checksum(
        LOCAL_V6, REMOTE_V6, translated_icmp)
    struct.pack_into("!H", translated_icmp, 2, translated_checksum)

    assert len(accepted_quote) == 65499
    assert len(packets[0]["layers"][2]["data"]) + 20 == 65527
    assert len(rejected_quote) == 65500
    assert len(packets[1]["layers"][2]["data"]) + 20 == 65528
    assert len(translated_quote) == 65527
    assert len(translated_icmp) == 65535
    assert icmpv6_checksum(LOCAL_V6, REMOTE_V6, translated_icmp) == 0

    max_fragment_payload = (65535 - 40 - 8) & ~7
    fragment_payloads = (
        bytes(translated_icmp[:max_fragment_payload]),
        bytes(translated_icmp[max_fragment_payload:]),
    )
    fragment_fields = (1, max_fragment_payload)
    fragment_checks = []
    for fragment_payload, fragment_field in zip(
            fragment_payloads, fragment_fields):
        outer_fragment = (struct.pack(
            "!BBHI", 58, 0, fragment_field, 0x7100)
                          + fragment_payload)
        fragment_checks.append({
            "count": 1,
            "packet": {
                "direction": "rx",
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(outer_fragment),
                        "next_header": 44,
                        "hop_limit": 254,
                        "src": LOCAL_V6,
                        "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "raw",
                        "data": list(outer_fragment),
                    },
                ],
            },
        })

    ICMP_QUOTE_LIMIT_FIXTURE.write_text(
        json.dumps(packets[0], separators=(",", ":")) + "\n")
    ICMP_QUOTE_LIMIT_REJECTED_FIXTURE.write_text(
        json.dumps(packets[1], separators=(",", ":")) + "\n")
    ICMP_QUOTE_LIMIT_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 2,
            "checks": fragment_checks,
        }, separators=(",", ":")) + "\n")


def udp_segment_for_zero_output_checksum(output_src, output_dst,
                                         source_src, source_dst,
                                         sport, dport, payload_prefix):
    payload = bytearray(payload_prefix + b"\0\0")
    length = 8 + len(payload)
    segment = bytearray(struct.pack("!HHHH", sport, dport, length, 0)
                        + payload)
    output_checksum = (ipv4_transport_checksum
                       if ipaddress.ip_address(output_src).version == 4
                       else ipv6_transport_checksum)
    source_checksum = (ipv4_transport_checksum
                       if ipaddress.ip_address(source_src).version == 4
                       else ipv6_transport_checksum)

    for correction in range(0x10000):
        struct.pack_into("!H", segment, len(segment) - 2, correction)
        if output_checksum(output_src, output_dst, 17, segment) == 0:
            break
    else:
        raise AssertionError("could not construct a computed-zero UDP vector")

    source_value = source_checksum(source_src, source_dst, 17, segment)
    assert source_value not in (0, 0xffff)
    struct.pack_into("!H", segment, 6, source_value)
    assert source_checksum(source_src, source_dst, 17, segment) == 0

    output_segment = bytearray(segment)
    struct.pack_into("!H", output_segment, 6, 0xffff)
    assert output_checksum(output_src, output_dst, 17, output_segment) == 0
    return bytes(segment), bytes(output_segment)


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
    assert checksum(ipv4) == 0

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


def generate_config_ranges():
    cases = (
        "v4-underflow",
        "v4-overflow",
        "v4-conversion-overflow",
        "v6-underflow",
        "v6-overflow",
        "v6-conversion-overflow",
        "ea-underflow",
        "ea-overflow",
        "ea-conversion-overflow",
        "psid-offset-underflow",
        "psid-offset-overflow",
        "psid-offset-conversion-overflow",
        "psid-length-underflow",
        "psid-length-overflow",
        "style-invalid",
        "fmr-underflow",
        "fmr-overflow",
        "fmr-conversion-overflow",
    )
    CONFIG_RANGES_DIR.mkdir(parents=True, exist_ok=True)
    for old_fixture in CONFIG_RANGES_DIR.glob("inject-case-*.jsonl"):
        old_fixture.unlink()

    checks = []
    for index, case_name in enumerate(cases, start=1):
        marker = f"RANGE-{index:02d}-OK".encode()
        sport = 46000 + index
        dport = 47000 + index
        identification = 0xc100 + index
        segment = transport_segment(
            "192.168.1.100", "8.8.8.8", 17, sport, dport, marker)
        packet = ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 17, identification,
            0, False, segment)
        fixture = (CONFIG_RANGES_DIR
                   / f"inject-case-{index:02d}-{case_name}.jsonl")
        fixture.write_text(
            json.dumps(packet, separators=(",", ":")) + "\n")

        translated_segment = bytearray(segment)
        struct.pack_into("!H", translated_segment, 6, 0)
        translated_checksum = ipv6_transport_checksum(
            LOCAL_V6, REMOTE_V6, 17, translated_segment)
        assert translated_checksum != 0
        struct.pack_into(
            "!H", translated_segment, 6, translated_checksum)
        assert ipv6_transport_checksum(
            LOCAL_V6, REMOTE_V6, 17, translated_segment) == 0

        forwarded_header = ipv4_header(
            "192.168.1.100", "8.8.8.8", 17, len(segment),
            identification=identification, ttl=254)
        source_checksum = struct.unpack_from("!H", segment, 6)[0]
        checks.extend((
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip",
                            "version": 4,
                            "ihl": 5,
                            "tos": 0,
                            "len": 20 + len(segment),
                            "id": identification,
                            "ttl": 254,
                            "proto": 17,
                            "chksum": struct.unpack_from(
                                "!H", forwarded_header, 10)[0],
                            "src": "192.168.1.100",
                            "dst": "8.8.8.8",
                            "options": [],
                        },
                        {
                            "layertype": "Udp",
                            "sport": sport,
                            "dport": dport,
                            "len": len(segment),
                            "chksum": source_checksum,
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(marker),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(translated_segment),
                            "next_header": 17,
                            "hop_limit": 254,
                            "src": LOCAL_V6,
                            "dst": REMOTE_V6,
                        },
                        {
                            "layertype": "Udp",
                            "sport": sport,
                            "dport": dport,
                            "len": len(translated_segment),
                            "chksum": translated_checksum,
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(marker),
                        },
                    ],
                },
            },
        ))

    CONFIG_RANGES_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": len(cases),
            "checks": checks,
        }, separators=(",", ":")) + "\n")

    accepted = (
        ("lower", "range-low", "0.0.0.0", 0, "::", 0,
         "NONE", 0, 0, 0),
        ("upper", "range-high", "192.0.2.1", 32,
         "2001:db8:ff::1", 128, "NONE", 32, 15, 1),
        ("rfc6052", "range-rfc", "0.0.0.0", 0,
         "2001:db8:64::", 96, "RFC6052", 0, 0, 0),
        ("map-psid-zero", "range-map0", "192.0.2.0", 24,
         "2001:db8:70::", 64, "MAP", 8, 15, 0),
        ("map0-psid-sixteen", "range-map16", "192.0.2.1", 32,
         "2001:db8:80::", 96, "MAP0", 16, 0, 1),
    )
    for (snapshot, device, v4, v4_len, v6, v6_len,
         style, ea_len, psid_offset, fmr_flag) in accepted:
        config = (
            f"local.v4 {v4}/{v4_len} "
            f"local.v6 {v6}/{v6_len} "
            f"local.style {style} local.ea-len {ea_len} "
            f"local.psid-offset {psid_offset} "
            f"local.fmr-flag {fmr_flag} "
            "remote.v4 8.8.8.8/32 "
            "remote.v6 2001:4860:4860::8888/128 "
            "remote.style NONE remote.ea-len 0 remote.psid-offset 0 "
            "remote.fmr-flag 0 debug 0")
        config = config[:199]
        expected_path = Path(
            f"test-harness/test-data/expected/"
            f"config-ranges-accepted-{snapshot}.txt")
        expected_path.write_text(
            f"add {device}\nconfig {device} {config}\n\n")


def generate_map_zero_prefix():
    ipv4_local = "192.0.2.33"
    ipv4_remote = "8.8.8.8"
    ipv6_prefix = ipaddress.IPv6Network("2001:db8:100:200::/64")
    ipv4_bytes = ipaddress.IPv4Address(ipv4_local).packed
    mapped_bytes = bytearray(ipv6_prefix.network_address.packed)

    # EA length 32 copies the complete IPv4 address after the /64 rule
    # prefix. MAP's IID retains the low 16 IPv4 bits and a zero PSID.
    mapped_bytes[8:12] = ipv4_bytes
    mapped_bytes[12:14] = ipv4_bytes[2:4]
    mapped_bytes[14:16] = b"\0\0"
    mapped = str(ipaddress.IPv6Address(bytes(mapped_bytes)))
    assert mapped == "2001:db8:100:200:c000:221:221:0"
    assert mapped_bytes[:8] == ipv6_prefix.network_address.packed[:8]
    assert mapped_bytes[8:12] == ipv4_bytes
    assert mapped_bytes[12:14] == ipv4_bytes[2:4]
    assert mapped_bytes[14:16] == b"\0\0"

    v4_marker = b"MAP-ZERO-V4V6"
    v6_marker = b"MAP-ZERO-V6V4"
    v4_sport, v4_dport = 54001, 55001
    v6_sport, v6_dport = 54002, 55002
    identification = 0xe001

    v4_source_segment = transport_segment(
        ipv4_local, ipv4_remote, 17, v4_sport, v4_dport, v4_marker)
    v4_packet = ipv4_fragment_packet(
        ipv4_local, ipv4_remote, 17, identification,
        0, False, v4_source_segment)

    v6_source_segment = transport_segment(
        REMOTE_V6, mapped, 17, v6_sport, v6_dport, v6_marker)
    v6_packet = {
        "timestamp_us": 1100000,
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
                "payload_length": len(v6_source_segment),
                "next_header": 17,
                "hop_limit": 64,
                "src": REMOTE_V6,
                "dst": mapped,
            },
            {"layertype": "raw", "data": list(v6_source_segment)},
        ],
    }
    MAP_ZERO_PREFIX_FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    MAP_ZERO_PREFIX_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in (v4_packet, v6_packet)))

    v6_output_segment = transport_segment(
        mapped, REMOTE_V6, 17, v4_sport, v4_dport, v4_marker)
    v4_output_segment = transport_segment(
        ipv4_remote, ipv4_local, 17, v6_sport, v6_dport, v6_marker)
    forwarded_header = ipv4_header(
        ipv4_local, ipv4_remote, 17, len(v4_source_segment),
        identification=identification, ttl=254)
    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }
    checks = [
        {
            "count": 1,
            "packet": {
                "direction": "tx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip", "version": 4, "ihl": 5,
                        "tos": 0, "len": 20 + len(v4_source_segment),
                        "id": identification, "flags": unfragmented_flags,
                        "ttl": 254, "proto": 17,
                        "chksum": struct.unpack_from(
                            "!H", forwarded_header, 10)[0],
                        "src": ipv4_local, "dst": ipv4_remote,
                        "options": [],
                    },
                    {
                        "layertype": "Udp", "sport": v4_sport,
                        "dport": v4_dport, "len": len(v4_source_segment),
                        "chksum": struct.unpack_from(
                            "!H", v4_source_segment, 6)[0],
                    },
                    {"layertype": "raw", "data_prefix": list(v4_marker)},
                ],
            },
        },
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(v6_output_segment),
                        "next_header": 17, "hop_limit": 254,
                        "src": mapped, "dst": REMOTE_V6,
                    },
                    {
                        "layertype": "Udp", "sport": v4_sport,
                        "dport": v4_dport, "len": len(v6_output_segment),
                        "chksum": struct.unpack_from(
                            "!H", v6_output_segment, 6)[0],
                    },
                    {"layertype": "raw", "data_prefix": list(v4_marker)},
                ],
            },
        },
        {
            "count": 1,
            "packet": {
                "direction": "tx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ipv6",
                        "version_class": 0x60000000,
                        "payload_length": len(v6_source_segment),
                        "next_header": 17, "hop_limit": 63,
                        "src": REMOTE_V6, "dst": mapped,
                    },
                    {
                        "layertype": "Udp", "sport": v6_sport,
                        "dport": v6_dport, "len": len(v6_source_segment),
                        "chksum": struct.unpack_from(
                            "!H", v6_source_segment, 6)[0],
                    },
                    {"layertype": "raw", "data_prefix": list(v6_marker)},
                ],
            },
        },
        {
            "count": 1,
            "packet": {
                "direction": "rx",
                "valid_checksums": True,
                "layers": [
                    {
                        "layertype": "Ip", "version": 4, "ihl": 5,
                        "tos": 0, "len": 20 + len(v4_output_segment),
                        "flags": unfragmented_flags, "ttl": 63,
                        "proto": 17, "src": ipv4_remote,
                        "dst": ipv4_local, "options": [],
                    },
                    {
                        "layertype": "Udp", "sport": v6_sport,
                        "dport": v6_dport, "len": len(v4_output_segment),
                        "chksum": struct.unpack_from(
                            "!H", v4_output_segment, 6)[0],
                    },
                    {"layertype": "raw", "data_prefix": list(v6_marker)},
                ],
            },
        },
    ]
    MAP_ZERO_PREFIX_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({"expected_rx_count": 2, "checks": checks},
                     separators=(",", ":")) + "\n")

    config = (
        "local.v4 0.0.0.0/0 "
        "local.v6 2001:db8:100:200::/64 local.style MAP "
        "local.ea-len 32 local.psid-offset 0 local.fmr-flag 0 "
        "remote.v4 8.8.8.8/32 "
        "remote.v6 2001:4860:4860::8888/128 remote.style NONE "
        "remote.ea-len 0 remote.psid-offset 0 remote.fmr-flag 0 debug 0")
    MAP_ZERO_PREFIX_CONFIG_EXPECTED.write_text(
        f"add nat46dev\nconfig nat46dev {config[:199]}\n\n")


def generate_remove_semantic_rule():
    local_v4 = "192.0.2.61"
    remote_v4 = "198.51.100.71"
    local_v6 = "2001:db8:1111:2222:3333:4444:5555:6666"
    target_remote_v6 = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1111"
    near_remote_v6 = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:2222"

    def serialized_rule(remote_v6):
        return (
            f"local.v4 {local_v4}/32 local.v6 {local_v6}/128 "
            "local.style NONE local.ea-len 7 local.psid-offset 5 "
            "local.fmr-flag 1 "
            f"remote.v4 {remote_v4}/32 remote.v6 {remote_v6}/128 "
            "remote.style NONE remote.ea-len 9 remote.psid-offset 6 "
            "remote.fmr-flag 1 debug 0")

    target_rule = serialized_rule(target_remote_v6)
    near_rule = serialized_rule(near_remote_v6)
    assert len(target_rule) == len(near_rule) == 304
    assert target_rule[:199] == near_rule[:199]
    assert next(i for i, values in enumerate(zip(target_rule, near_rule))
                if values[0] != values[1]) == 215

    cases = (
        ("target-before", target_remote_v6, b"SEM-TARGET-PRE01",
         62001, 63001, 0x5e01a101, 1000000, 1),
        ("near-before", near_remote_v6, b"SEM-NEAR---PRE02",
         62002, 63002, 0x5e01a102, 1100000, 1),
        ("target-after", target_remote_v6, b"SEM-TARGET-POST3",
         62003, 63003, 0x5e01a103, 1200000, 0),
        ("near-after", near_remote_v6, b"SEM-NEAR--POST04",
         62004, 63004, 0x5e01a104, 1300000, 1),
    )
    REMOVE_SEMANTIC_RULE_DIR.mkdir(parents=True, exist_ok=True)
    checks = []
    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }
    for (name, source_v6, marker, sport, dport, fragment_id,
         timestamp_us, output_count) in cases:
        source_segment = transport_segment(
            source_v6, local_v6, 17, sport, dport, marker)
        assert struct.unpack_from("!H", source_segment, 6)[0] != 0
        fragment_header = struct.pack("!BBHI", 17, 0, 0, fragment_id)
        fixture = {
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
                    "payload_length": len(fragment_header)
                                      + len(source_segment),
                    "next_header": 44, "hop_limit": 64,
                    "src": source_v6, "dst": local_v6,
                },
                {"layertype": "raw",
                 "data": list(fragment_header + source_segment)},
            ],
        }
        (REMOVE_SEMANTIC_RULE_DIR
         / f"inject-valid-{name}.jsonl").write_text(
            json.dumps(fixture, separators=(",", ":")) + "\n")

        output_segment = bytearray(source_segment)
        struct.pack_into("!H", output_segment, 6, 0)
        output_checksum = ipv4_transport_checksum(
            remote_v4, local_v4, 17, output_segment)
        assert output_checksum != 0
        struct.pack_into("!H", output_segment, 6, output_checksum)
        assert ipv4_transport_checksum(
            remote_v4, local_v4, 17, output_segment) == 0
        output_id = fragment_id & 0xffff
        output_header = ipv4_header(
            remote_v4, local_v4, 17, len(output_segment),
            identification=output_id, ttl=63)
        checks.extend((
            {
                "count": 1,
                "packet": {
                    "direction": "tx", "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(fragment_header)
                                              + len(source_segment),
                            "next_header": 44, "hop_limit": 63,
                            "src": source_v6, "dst": local_v6,
                        },
                        {"layertype": "raw",
                         "data_prefix": list(
                             fragment_header + source_segment)},
                    ],
                },
            },
            {
                "count": output_count,
                "packet": {
                    "direction": "rx", "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip", "version": 4, "ihl": 5,
                            "tos": 0, "len": 20 + len(output_segment),
                            "id": output_id, "flags": unfragmented_flags,
                            "ttl": 63, "proto": 17,
                            "chksum": struct.unpack_from(
                                "!H", output_header, 10)[0],
                            "src": remote_v4, "dst": local_v4,
                            "options": [],
                        },
                        {
                            "layertype": "Udp", "sport": sport,
                            "dport": dport, "len": len(output_segment),
                            "chksum": output_checksum,
                        },
                        {"layertype": "raw",
                         "data_prefix": list(marker)},
                    ],
                },
            },
        ))

    REMOVE_SEMANTIC_RULE_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({"expected_rx_count": 3, "checks": checks},
                     separators=(",", ":")) + "\n")
    empty_rule = (
        "local.v4 0.0.0.0/0 local.v6 ::/0 local.style NONE "
        "local.ea-len 0 local.psid-offset 0 local.fmr-flag 0 "
        "remote.v4 0.0.0.0/0 remote.v6 ::/0 remote.style NONE "
        "remote.ea-len 0 remote.psid-offset 0 remote.fmr-flag 0 debug 0")
    REMOVE_SEMANTIC_RULE_CONFIG_EXPECTED.write_text(
        "add nat46dev\n"
        f"insert nat46dev {near_rule[:199]}\n"
        f"config nat46dev {empty_rule[:199]}\n\n")


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


def ipv6_tcp_packet(src, dst, sport, dport, timestamp_us):
    tcp = bytearray(struct.pack(
        "!HHIIBBHHH", sport, dport, 0, 0, 0x50, 2, 8192, 0, 0))
    struct.pack_into(
        "!H", tcp, 16,
        ipv6_transport_checksum(src, dst, 6, tcp))
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
                "payload_length": len(tcp),
                "next_header": 6,
                "hop_limit": 64,
                "src": src,
                "dst": dst,
            },
            {"layertype": "raw", "data": list(tcp)},
        ],
    }


def rfc6052_address(prefix, ipv4):
    network = ipaddress.IPv6Network(prefix)
    ipv6 = bytearray(network.network_address.packed)
    ipv4 = ipaddress.IPv4Address(ipv4).packed
    prefix_length = network.prefixlen

    if prefix_length == 96:
        ipv6[12:16] = ipv4
    else:
        first_part = (64 - prefix_length) // 8
        ipv6[prefix_length // 8:8] = ipv4[:first_part]
        ipv6[9:9 + 4 - first_part] = ipv4[first_part:]

    return ipv6


def generate_rfc6052_prefix_lengths():
    accepted = (
        (32, "2001:db8::/32"),
        (40, "2001:db9:100::/40"),
        (48, "2001:dba:2::/48"),
        (56, "2001:dbb:3:400::/56"),
        (64, "2001:dbc:4:5::/64"),
        (96, "2001:dbd:5:6::/96"),
    )
    rejected = (31, 33, 39, 41, 47, 49, 55, 57, 63, 65, 95, 97)
    rejected_prefixes = (
        "2001:db8::/31",
        "2001:db8::/33",
        "2001:db9::/39",
        "2001:db9::/41",
        "2001:dba::/47",
        "2001:dba::/49",
        "2001:dbb::/55",
        "2001:dbb::/57",
        "2001:dbc:4::/63",
        "2001:dbc:4::/65",
        "2001:dbd:5::/95",
        "2001:dbd:5::/97",
    )
    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }

    assert tuple(length for length, _prefix in accepted) == (
        32, 40, 48, 56, 64, 96)
    assert tuple(ipaddress.IPv6Network(prefix).prefixlen
                 for prefix in rejected_prefixes) == rejected

    RFC6052_PREFIX_LENGTHS_DIR.mkdir(parents=True, exist_ok=True)
    for pattern in ("inject-valid-*.jsonl", "inject-case-*.jsonl"):
        for old_fixture in RFC6052_PREFIX_LENGTHS_DIR.glob(pattern):
            old_fixture.unlink()

    checks = []
    for index, (prefix_length, prefix) in enumerate(accepted, start=1):
        embedded_bytes = bytes(rfc6052_address(prefix, "8.8.8.8"))
        embedded = str(ipaddress.IPv6Address(embedded_bytes))
        network = ipaddress.IPv6Network(prefix)
        assert ipaddress.IPv6Address(embedded) in network
        if prefix_length == 96:
            assert embedded_bytes[12:] == ipaddress.IPv4Address(
                "8.8.8.8").packed
        else:
            assert embedded_bytes[8] == 0
            suffix_start = 9 + 4 - ((64 - prefix_length) // 8)
            assert embedded_bytes[suffix_start:] == bytes(16 - suffix_start)

        v4_marker = f"R6052-A{prefix_length}-4TO6".encode()
        v6_marker = f"R6052-A{prefix_length}-6TO4".encode()
        v4_sport = 50000 + index * 2
        v4_dport = 51000 + index * 2
        v6_sport = v4_sport + 1
        v6_dport = v4_dport + 1
        identification = 0xd200 + index

        v4_source_segment = transport_segment(
            "192.168.1.100", "8.8.8.8", 17,
            v4_sport, v4_dport, v4_marker)
        v4_packet = ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 17, identification,
            0, False, v4_source_segment)
        v4_packet["timestamp_us"] = 1000000

        v6_source_segment = transport_segment(
            embedded, LOCAL_V6, 17, v6_sport, v6_dport, v6_marker)
        v6_packet = {
            "timestamp_us": 1100000,
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
                    "payload_length": len(v6_source_segment),
                    "next_header": 17,
                    "hop_limit": 64,
                    "src": embedded,
                    "dst": LOCAL_V6,
                },
                {"layertype": "raw", "data": list(v6_source_segment)},
            ],
        }
        valid_fixture = (RFC6052_PREFIX_LENGTHS_DIR
                         / f"inject-valid-{prefix_length}.jsonl")
        valid_fixture.write_text("".join(
            json.dumps(packet, separators=(",", ":")) + "\n"
            for packet in (v4_packet, v6_packet)))

        v6_output_segment = transport_segment(
            LOCAL_V6, embedded, 17, v4_sport, v4_dport, v4_marker)
        v4_output_segment = transport_segment(
            "8.8.8.8", "192.168.1.100", 17,
            v6_sport, v6_dport, v6_marker)
        forwarded_v4_header = ipv4_header(
            "192.168.1.100", "8.8.8.8", 17,
            len(v4_source_segment), identification=identification, ttl=254)
        checks.extend((
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip", "version": 4, "ihl": 5,
                            "tos": 0, "len": 20 + len(v4_source_segment),
                            "id": identification,
                            "flags": unfragmented_flags, "ttl": 254,
                            "proto": 17,
                            "chksum": struct.unpack_from(
                                "!H", forwarded_v4_header, 10)[0],
                            "src": "192.168.1.100", "dst": "8.8.8.8",
                            "options": [],
                        },
                        {
                            "layertype": "Udp", "sport": v4_sport,
                            "dport": v4_dport,
                            "len": len(v4_source_segment),
                            "chksum": struct.unpack_from(
                                "!H", v4_source_segment, 6)[0],
                        },
                        {"layertype": "raw",
                         "data_prefix": list(v4_marker)},
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(v6_output_segment),
                            "next_header": 17, "hop_limit": 254,
                            "src": LOCAL_V6, "dst": embedded,
                        },
                        {
                            "layertype": "Udp", "sport": v4_sport,
                            "dport": v4_dport,
                            "len": len(v6_output_segment),
                            "chksum": struct.unpack_from(
                                "!H", v6_output_segment, 6)[0],
                        },
                        {"layertype": "raw",
                         "data_prefix": list(v4_marker)},
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(v6_source_segment),
                            "next_header": 17, "hop_limit": 63,
                            "src": embedded, "dst": LOCAL_V6,
                        },
                        {
                            "layertype": "Udp", "sport": v6_sport,
                            "dport": v6_dport,
                            "len": len(v6_source_segment),
                            "chksum": struct.unpack_from(
                                "!H", v6_source_segment, 6)[0],
                        },
                        {"layertype": "raw",
                         "data_prefix": list(v6_marker)},
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip", "version": 4, "ihl": 5,
                            "tos": 0, "len": 20 + len(v4_output_segment),
                            "flags": unfragmented_flags, "ttl": 63,
                            "proto": 17, "src": "8.8.8.8",
                            "dst": "192.168.1.100", "options": [],
                        },
                        {
                            "layertype": "Udp", "sport": v6_sport,
                            "dport": v6_dport,
                            "len": len(v4_output_segment),
                            "chksum": struct.unpack_from(
                                "!H", v4_output_segment, 6)[0],
                        },
                        {"layertype": "raw",
                         "data_prefix": list(v6_marker)},
                    ],
                },
            },
        ))

    baseline_prefix = "2001:dbd:5:6::/96"
    baseline_embedded = str(ipaddress.IPv6Address(
        bytes(rfc6052_address(baseline_prefix, "8.8.8.8"))))
    for index, prefix_length in enumerate(rejected, start=1):
        marker = f"R6052-R{prefix_length}-OK".encode()
        sport = 52000 + index
        dport = 53000 + index
        identification = 0xd300 + index
        source_segment = transport_segment(
            "192.168.1.100", "8.8.8.8", 17, sport, dport, marker)
        packet = ipv4_fragment_packet(
            "192.168.1.100", "8.8.8.8", 17, identification,
            0, False, source_segment)
        rejected_fixture = (RFC6052_PREFIX_LENGTHS_DIR
                            / (f"inject-case-{index:02d}-prefix-"
                               f"{prefix_length}.jsonl"))
        rejected_fixture.write_text(
            json.dumps(packet, separators=(",", ":")) + "\n")

        output_segment = transport_segment(
            LOCAL_V6, baseline_embedded, 17, sport, dport, marker)
        forwarded_header = ipv4_header(
            "192.168.1.100", "8.8.8.8", 17, len(source_segment),
            identification=identification, ttl=254)
        checks.extend((
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip", "version": 4, "ihl": 5,
                            "tos": 0, "len": 20 + len(source_segment),
                            "id": identification,
                            "flags": unfragmented_flags, "ttl": 254,
                            "proto": 17,
                            "chksum": struct.unpack_from(
                                "!H", forwarded_header, 10)[0],
                            "src": "192.168.1.100", "dst": "8.8.8.8",
                            "options": [],
                        },
                        {
                            "layertype": "Udp", "sport": sport,
                            "dport": dport, "len": len(source_segment),
                            "chksum": struct.unpack_from(
                                "!H", source_segment, 6)[0],
                        },
                        {"layertype": "raw", "data_prefix": list(marker)},
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(output_segment),
                            "next_header": 17, "hop_limit": 254,
                            "src": LOCAL_V6, "dst": baseline_embedded,
                        },
                        {
                            "layertype": "Udp", "sport": sport,
                            "dport": dport, "len": len(output_segment),
                            "chksum": struct.unpack_from(
                                "!H", output_segment, 6)[0],
                        },
                        {"layertype": "raw", "data_prefix": list(marker)},
                    ],
                },
            },
        ))

    RFC6052_PREFIX_LENGTHS_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": 2 * len(accepted) + len(rejected),
            "checks": checks,
        }, separators=(",", ":")) + "\n")


def icmpv6_error_packet(quoted_packet, timestamp_us=1000000,
                        trailing_data=b"", icmp_type=1, icmp_code=0,
                        field=0):
    icmp = bytearray(
        struct.pack("!BBHI", icmp_type, icmp_code, 0, field) + quoted_packet)
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
    generate_config_ranges()
    generate_map_zero_prefix()
    generate_remove_semantic_rule()
    generate_rfc6052_prefix_lengths()
    generate_icmp_embedded_headers()
    generate_icmp_quote_output_limit()
    generate_quoted_fragmented_icmp()
    generate_quoted_source_routes()
    generate_quoted_ipv4_padding()
    generate_quoted_icmp_echo_checksums()

    rfc6052_prefixes = (
        (32, "2001:db8::/32"),
        (40, "2001:db9:100::/40"),
        (48, "2001:dba:2::/48"),
        (56, "2001:dbb:3:400::/56"),
        (64, "2001:dbc:4:5::/64"),
        (96, "2001:dbd:5:6::/96"),
    )
    rfc6052_packets = []
    rfc6052_checks = []
    timestamp_us = 1000000

    for prefix_length, prefix in rfc6052_prefixes:
        valid = rfc6052_address(prefix, "8.8.8.8")
        variants = [("valid", valid, 6000 + prefix_length, 1)]

        invalid_u = bytearray(valid)
        invalid_u[8] = 1
        variants.append(("u", invalid_u, 6100 + prefix_length, 0))

        if prefix_length != 96:
            invalid_suffix = bytearray(valid)
            invalid_suffix[15] = 1
            variants.append(
                ("suffix", invalid_suffix, 6200 + prefix_length, 0))

        for _variant, address, dport, expected_outputs in variants:
            source = str(ipaddress.IPv6Address(bytes(address)))
            rfc6052_packets.append(ipv6_tcp_packet(
                source, LOCAL_V6, 40000 + prefix_length, dport,
                timestamp_us))
            timestamp_us += 100000
            rfc6052_checks.extend((
                {
                    "count": 1,
                    "packet": {
                        "direction": "tx",
                        "valid_checksums": True,
                        "layers": [
                            {
                                "layertype": "Ipv6",
                                "src": source,
                                "dst": LOCAL_V6,
                                "next_header": 6,
                            },
                            {
                                "layertype": "Tcp",
                                "sport": 40000 + prefix_length,
                                "dport": dport,
                                "nonzero_fields": ["chksum"],
                            },
                        ],
                    },
                },
                {
                    "count": expected_outputs,
                    "packet": {
                        "direction": "rx",
                        "valid_checksums": True,
                        "layers": [
                            {
                                "layertype": "Ip",
                                "src": "8.8.8.8",
                                "dst": "192.168.1.100",
                                "proto": 6,
                            },
                            {
                                "layertype": "Tcp",
                                "sport": 40000 + prefix_length,
                                "dport": dport,
                                "nonzero_fields": ["chksum"],
                            },
                        ],
                    },
                },
            ))

    RFC6052_CANONICAL_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in rfc6052_packets))
    RFC6052_CANONICAL_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps({
            "expected_rx_count": len(rfc6052_prefixes),
            "checks": rfc6052_checks,
        }, separators=(",", ":")) + "\n")

    v4_to_v6_source, v4_to_v6_output = (
        udp_segment_for_zero_output_checksum(
            LOCAL_V6, REMOTE_V6,
            "192.168.1.100", "8.8.8.8",
            41001, 42001, b"V4-TO-V6-ZERO:"))
    v6_to_v4_source, v6_to_v4_output = (
        udp_segment_for_zero_output_checksum(
            "8.8.8.8", "192.168.1.100",
            REMOTE_V6, LOCAL_V6,
            41002, 42002, b"V6-TO-V4-ZERO:"))
    quoted_source, quoted_output = udp_segment_for_zero_output_checksum(
        "192.168.1.100", "8.8.8.8",
        LOCAL_V6, REMOTE_V6,
        41003, 42003, b"QUOTE-V6-V4-ZERO::")

    v4_to_v6_packet = ipv4_fragment_packet(
        "192.168.1.100", "8.8.8.8", 17, 0x2468, 0, False,
        v4_to_v6_source)
    v6_to_v4_packet = ipv6_extension_packet(
        17, b"", v6_to_v4_source, 1100000)
    quoted_ipv6 = (ipv6_header(len(quoted_source), 17,
                               LOCAL_V6, REMOTE_V6)
                   + quoted_source)
    quoted_packet = icmpv6_error_packet(quoted_ipv6, timestamp_us=1200000)
    UDP_ZERO_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in (v4_to_v6_packet, v6_to_v4_packet, quoted_packet)))

    quoted_ipv4 = bytearray(struct.pack(
        "!BBHHHBBH", 0x45, 0, 20 + len(quoted_output), 0, 0, 64, 17, 0))
    quoted_ipv4.extend(ipaddress.IPv4Address("192.168.1.100").packed)
    quoted_ipv4.extend(ipaddress.IPv4Address("8.8.8.8").packed)
    struct.pack_into("!H", quoted_ipv4, 10, checksum(quoted_ipv4))

    unfragmented_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }
    udp_zero_spec = {
        "expected_rx_count": 3,
        "checks": [
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip",
                            "version": 4,
                            "ihl": 5,
                            "tos": 0,
                            "len": 20 + len(v4_to_v6_source),
                            "id": 0x2468,
                            "flags": unfragmented_flags,
                            "ttl": 254,
                            "proto": 17,
                            "src": "192.168.1.100",
                            "dst": "8.8.8.8",
                            "options": [],
                        },
                        {
                            "layertype": "Udp",
                            "sport": 41001,
                            "dport": 42001,
                            "len": len(v4_to_v6_source),
                            "chksum": struct.unpack_from(
                                "!H", v4_to_v6_source, 6)[0],
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(v4_to_v6_source[8:]),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(v4_to_v6_output),
                            "next_header": 17,
                            "hop_limit": 254,
                            "src": LOCAL_V6,
                            "dst": REMOTE_V6,
                        },
                        {
                            "layertype": "Udp",
                            "sport": 41001,
                            "dport": 42001,
                            "len": len(v4_to_v6_output),
                            "chksum": 0xffff,
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(v4_to_v6_output[8:]),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": len(v6_to_v4_source),
                            "next_header": 17,
                            "hop_limit": 63,
                            "src": REMOTE_V6,
                            "dst": LOCAL_V6,
                        },
                        {
                            "layertype": "Udp",
                            "sport": 41002,
                            "dport": 42002,
                            "len": len(v6_to_v4_source),
                            "chksum": struct.unpack_from(
                                "!H", v6_to_v4_source, 6)[0],
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(v6_to_v4_source[8:]),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip",
                            "version": 4,
                            "ihl": 5,
                            "tos": 0,
                            "len": 20 + len(v6_to_v4_output),
                            "flags": unfragmented_flags,
                            "ttl": 63,
                            "proto": 17,
                            "src": "8.8.8.8",
                            "dst": "192.168.1.100",
                            "options": [],
                        },
                        {
                            "layertype": "Udp",
                            "sport": 41002,
                            "dport": 42002,
                            "len": len(v6_to_v4_output),
                            "chksum": 0xffff,
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(v6_to_v4_output[8:]),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": 8 + len(quoted_ipv6),
                            "next_header": 58,
                            "hop_limit": 63,
                            "src": REMOTE_V6,
                            "dst": LOCAL_V6,
                        },
                        {
                            "layertype": "Icmpv6",
                            "type_": 1,
                            "code": 0,
                            "nonzero_fields": ["checksum"],
                        },
                        {
                            "layertype": "icmpv6DestUnreach",
                            "unused": 0,
                            "invoking_packet": list(quoted_ipv6),
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "layers": [
                        {
                            "layertype": "Ip",
                            "version": 4,
                            "ihl": 5,
                            "tos": 0,
                            "len": 28 + len(quoted_ipv4) + len(quoted_output),
                            "flags": unfragmented_flags,
                            "ttl": 63,
                            "proto": 1,
                            "src": "8.8.8.8",
                            "dst": "192.168.1.100",
                            "options": [],
                        },
                        {
                            "layertype": "Icmp",
                            "typ": 3,
                            "code": 1,
                            "nonzero_fields": ["chksum"],
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": list(
                                b"\0\0\0\0" + quoted_ipv4
                                + quoted_output),
                        },
                    ],
                },
            },
        ],
    }
    UDP_ZERO_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps(udp_zero_spec, separators=(",", ":")) + "\n")

    udp_padding_payload = b"UDP-DATAGRAM-PAYLOAD-OK!"
    udp_trailing_padding = (bytes.fromhex("de ad be ef ca fe f0 0d")
                            + b"NOT-UDP-PAYLOAD!")
    udp_declared_length = 8 + len(udp_padding_payload)
    udp_segment = bytearray(struct.pack(
        "!HHHH", 12345, 54321, udp_declared_length, 0)
        + udp_padding_payload)
    struct.pack_into(
        "!H", udp_segment, 6,
        ipv4_transport_checksum(
            "192.168.1.100", "8.8.8.8", 17, udp_segment))
    udp_padding_packet = ipv4_fragment_packet(
        "192.168.1.100", "8.8.8.8", 17, 0x1357, 0, False,
        udp_segment + udp_trailing_padding)
    UDP_PADDING_FIXTURE.write_text(
        json.dumps(udp_padding_packet, separators=(",", ":")) + "\n")

    udp_padding_data = list(udp_padding_payload + udp_trailing_padding)
    udp_padding_flags = {
        "reserved": False,
        "dont_fragment": False,
        "more_fragments": False,
        "fragment_offset": 0,
    }
    udp_padding_spec = {
        "expected_rx_count": 1,
        "checks": [
            {
                "count": 1,
                "packet": {
                    "direction": "tx",
                    "valid_checksums": True,
                    "udp_checksum_excludes_trailing_padding": True,
                    "layers": [
                        {
                            "layertype": "Ip",
                            "version": 4,
                            "ihl": 5,
                            "tos": 0,
                            "len": 76,
                            "id": 0x1357,
                            "flags": udp_padding_flags,
                            "ttl": 254,
                            "proto": 17,
                            "src": "192.168.1.100",
                            "dst": "8.8.8.8",
                            "options": [],
                        },
                        {
                            "layertype": "Udp",
                            "sport": 12345,
                            "dport": 54321,
                            "len": udp_declared_length,
                            "nonzero_fields": ["chksum"],
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": udp_padding_data,
                        },
                    ],
                },
            },
            {
                "count": 1,
                "packet": {
                    "direction": "rx",
                    "valid_checksums": True,
                    "udp_checksum_excludes_trailing_padding": True,
                    "layers": [
                        {
                            "layertype": "Ipv6",
                            "version_class": 0x60000000,
                            "payload_length": 56,
                            "next_header": 17,
                            "hop_limit": 254,
                            "src": LOCAL_V6,
                            "dst": REMOTE_V6,
                        },
                        {
                            "layertype": "Udp",
                            "sport": 12345,
                            "dport": 54321,
                            "len": udp_declared_length,
                            "nonzero_fields": ["chksum"],
                        },
                        {
                            "layertype": "raw",
                            "data_prefix": udp_padding_data,
                        },
                    ],
                },
            },
        ],
    }
    UDP_PADDING_EXPECTED.write_text(
        "# packet assertion\n"
        + json.dumps(udp_padding_spec, separators=(",", ":")) + "\n")

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

    quoted_fragment = struct.pack("!BBHI", 59, 0, 0x0002, 0x12345678)
    quoted_packet = (ipv6_header(len(quoted_fragment), 44,
                                 LOCAL_V6, REMOTE_V6)
                     + quoted_fragment)
    write_icmpv6_error_fixture(SMALL_ATOMIC_QUOTE_FIXTURE, quoted_packet)

    nonatomic_packets = []
    for index, (fragment_field, identification) in enumerate(
            ((0x0008, 0x12345678), (0x0001, 0x9abcdef0))):
        quoted_fragment = struct.pack(
            "!BBHI", 59, 0, fragment_field, identification)
        quoted_packet = (ipv6_header(len(quoted_fragment), 44,
                                     LOCAL_V6, REMOTE_V6)
                         + quoted_fragment)
        nonatomic_packets.append(icmpv6_error_packet(
            quoted_packet, timestamp_us=1000000 + index * 100000))
    NONATOMIC_QUOTE_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in nonatomic_packets))

    parameter_quoted_icmp = bytearray(
        bytes([128, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]))
    struct.pack_into(
        "!H", parameter_quoted_icmp, 2,
        icmpv6_checksum(LOCAL_V6, REMOTE_V6, parameter_quoted_icmp))
    parameter_quoted_packet = (
        ipv6_header(len(parameter_quoted_icmp), 58, LOCAL_V6, REMOTE_V6)
        + parameter_quoted_icmp)
    packet_too_big_packets = tuple(
        icmpv6_error_packet(
            parameter_quoted_packet, timestamp_us=1000000 + index * 100000,
            icmp_type=2, icmp_code=0, field=advertised_mtu)
        for index, advertised_mtu in enumerate((1280, 1500, 65535, 65536)))
    ICMP_PACKET_TOO_BIG_MTU_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in packet_too_big_packets))

    quoted_ipv4 = bytearray(struct.pack(
        "!BBHHHBBH", 0x45, 0, 40, 1, 0, 255, 6, 0))
    quoted_ipv4.extend(ipaddress.IPv4Address("8.8.8.8").packed)
    quoted_ipv4.extend(ipaddress.IPv4Address("192.168.1.100").packed)
    struct.pack_into("!H", quoted_ipv4, 10, checksum(quoted_ipv4))
    quoted_tcp = struct.pack(
        "!HHIIBBHHH", 81, 12345, 0, 0, 0x50, 2, 8192, 0, 0)
    icmp = bytearray(
        struct.pack("!BBHBBH", 3, 4, 0, 0x12, 0, 1500)
        + quoted_ipv4 + quoted_tcp)
    struct.pack_into("!H", icmp, 2, checksum(icmp))
    mtu_reserved_packet = ipv4_fragment_packet(
        "192.168.1.100", "8.8.8.8", 1, 1, 0, False, icmp)
    ICMP_MTU_RESERVED_BITS_FIXTURE.write_text(
        json.dumps(mtu_reserved_packet, separators=(",", ":")) + "\n")

    parameter_problem_packets = tuple(
        icmpv6_error_packet(
            parameter_quoted_packet, timestamp_us=1000000 + index * 100000,
            icmp_type=4, icmp_code=code, field=6)
        for index, code in enumerate((0, 1)))
    ICMP_PARAMETER_POINTER_FIXTURE.write_text("".join(
        json.dumps(packet, separators=(",", ":")) + "\n"
        for packet in parameter_problem_packets))
    parameter_problem_unmapped = icmpv6_error_packet(
        parameter_quoted_packet, icmp_type=4, icmp_code=0, field=2)
    ICMP_PARAMETER_POINTER_UNMAPPED_FIXTURE.write_text(
        json.dumps(parameter_problem_unmapped, separators=(",", ":")) + "\n")

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
