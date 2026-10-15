#!/usr/bin/env python3
"""Independent transcript/oracle checker. Does not import the simulator."""

import binascii
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "worked-examples" / "pivdata"

def require(condition, message):
    """Validate under normal and optimized Python alike."""
    if not condition:
        raise ValueError(message)


def check_selected_bytes(oracle):
    """Check successful selection independently, preserving the encoded TLV header."""
    request = bytes.fromhex(oracle["request_hex"])
    require(len(request) >= 8 and request[0] == 0xA3, "selection request header")
    require(1 <= request[1] <= 3, "selection identifier length")
    position = 2 + request[1]
    require(position < len(request), "missing selection tag length")
    tag_size = request[position]
    require(tag_size <= 3 and len(request) == position + 1 + tag_size + 4,
            "selection request length")
    tag = request[position + 1:position + 1 + tag_size]
    offset = int.from_bytes(request[-4:-2], "little")
    count = int.from_bytes(request[-2:], "little")
    response = bytes.fromhex(oracle["card_response_hex"])

    def bounds(start):
        require(0 <= start < len(response), "missing TLV tag")
        cursor = start + 1
        if response[start] & 31 == 31:
            while True:
                require(cursor < len(response), "truncated TLV tag")
                continuation = response[cursor] & 128
                cursor += 1
                if not continuation:
                    break
        encoded_tag = response[start:cursor]
        require(cursor < len(response), "missing TLV length")
        length = response[cursor]
        cursor += 1
        if length & 128:
            width = length & 127
            require(width and cursor + width <= len(response), "invalid TLV length")
            length = int.from_bytes(response[cursor:cursor + width], "big")
            cursor += width
        require(cursor + length <= len(response), "truncated TLV value")
        return encoded_tag, cursor, cursor + length

    selected = response
    if tag:
        _, cursor, end = bounds(0)
        require(end == len(response), "trailing bytes after outer TLV")
        matches = []
        while cursor < end:
            child_tag, _, child_end = bounds(cursor)
            if child_tag == tag:
                matches.append(response[cursor:child_end])
            cursor = child_end
        require(len(matches) == 1, "selection must have one matching child")
        selected = matches[0]
    require(offset <= len(selected), "selection offset out of range")
    expected = selected[offset:] if count == 0 else selected[offset:offset + count]
    require(expected.hex().upper() == oracle["expected_selected_hex"], "selection/range oracle")


def unpack_frame(encoded, reply, sequence):
    data = bytes.fromhex(encoded)
    require(8 <= len(data) <= 128, "frame size")
    require(data[:2] == bytes([0x53, 0x81 if reply else 1]), "address/direction")
    require(int.from_bytes(data[2:4], "little") == len(data), "length")
    require(data[4] == 4 + sequence, "sequence/control")
    require(binascii.crc_hqx(data[:-2], 0x1D0F) == int.from_bytes(data[-2:], "little"), "CRC")
    return data[5:-2]


def check(directory=DIRECTORY):
    manifest = json.loads((directory / "manifest.json").read_text())
    examples = json.loads((directory / "examples.json").read_text())
    require(examples["schema"] == manifest["schema"] == 1, "schema")
    require(examples["secure_channel"] is False, "Secure Channel example flag")
    require(examples["frame_limit"] == 128 and examples["fragment_limit"] == 114, "example limits")
    require(len(examples["cases"]) == len(manifest["cases"]), "case count")
    for source in manifest["sources"]:
        path = ROOT / source["path"]
        require(hashlib.sha256(path.read_bytes()).hexdigest() == source["sha256"], "source changed")
    for oracle, case in zip(manifest["cases"], examples["cases"]):
        require({k: v for k, v in case.items() if k != "exchanges"} == oracle, "fixture changed")
        provenance = oracle["provenance"]
        if provenance["kind"] == "captured":
            source = json.loads((ROOT / provenance["source"]).read_text())
            value = source
            for key in provenance["json_path"]:
                value = value[key]
            require(value.upper() == oracle["card_response_hex"], "response provenance")
            if "expected_selected_hex" in oracle:
                # Explicit offsets are independently recorded in the fixed manifest.
                start, stop = provenance["expected_response_slice"]
                require(bytes.fromhex(value)[start:stop].hex().upper() == oracle["expected_selected_hex"],
                        "captured selection provenance")
        else:
            require(provenance["kind"] == "synthetic" and provenance["reason"], "synthetic provenance")
        if "expected_selected_hex" in oracle:
            check_selected_bytes(oracle)
        sequence = 1
        collected = bytearray()
        total = None
        exchanges = case["exchanges"]
        delay = oracle.get("delay_polls", 0)
        require(len(exchanges) >= 2 + delay, "missing asynchronous completion")
        for index, row in enumerate(exchanges):
            command = unpack_frame(row["command_hex"], False, sequence)
            reply = unpack_frame(row["reply_hex"], True, sequence)
            if index == 0:
                require(command.hex().upper() == oracle["request_hex"], "request oracle")
                require(reply == b"\x40", "acceptance ACK")
            else:
                require(command == b"\x60", "non-POLL in transfer")
                if index <= delay:
                    require(reply == b"\x40", "pending operation must ACK")
                elif "expected_error" in oracle:
                    require(len(exchanges) == 2 + delay, "data after terminal error")
                    expected_error = b"\x8a" + oracle["expected_error"].to_bytes(2, "little")
                    if "status_word" in oracle:
                        expected_error += oracle["status_word"].to_bytes(2, "big")
                    require(reply == expected_error, "error oracle")
                else:
                    require(len(reply) >= 7 and reply[0] == 0x80, "data reply header")
                    size = int.from_bytes(reply[1:3], "little")
                    offset = int.from_bytes(reply[3:5], "little")
                    count = int.from_bytes(reply[5:7], "little")
                    require(size <= 65535 and offset == len(collected), "multipart order")
                    require(count == len(reply) - 7 and count <= 114, "fragment length")
                    require(offset + count <= size, "fragment exceeds total")
                    if total is not None:
                        require(size == total, "changing total")
                    total = size
                    collected.extend(reply[7:])
                    require(index == len(exchanges) - 1 or len(collected) < total, "data after completion")
            sequence = sequence % 3 + 1
        if "expected_selected_hex" in oracle:
            expected = bytes.fromhex(oracle["expected_selected_hex"])
            require(total == len(expected) and collected == expected, "oracle mismatch")
    return len(examples["cases"])


if __name__ == "__main__":
    print(f"Verified {check()} PIVGETDATA examples against fixed oracles and captured-source hashes")
