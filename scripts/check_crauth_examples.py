#!/usr/bin/env python3
"""Independent CRAUTH packet, reassembly, and source-capture checks."""
import binascii
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from check_sm_vci_examples import tlvs, verify_capture

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def packet(encoded, address, sequence):
    data = bytes.fromhex(encoded)
    require(len(data) >= 8 and data[0] == 0x53 and data[1] == address, "frame header")
    require(int.from_bytes(data[2:4], "little") == len(data), "packet length")
    require(data[4] == 4 | sequence, "sequence/control")
    require(binascii.crc_hqx(data[:-2], 0x1D0F) == int.from_bytes(data[-2:], "little"), "CRC")
    return data[5:-2]


def verify(document):
    vector = json.loads((ROOT / document["source"]).read_text())
    verify_capture(vector)
    op = vector["signing_operations"]["cak"]
    record = bytes.fromhex(document["record"])
    require(record == bytes.fromhex("FF119E" + op["challenge_hex"]), "marker/algorithm/key/challenge")
    expected_command = "0087119E267C2482008120" + op["challenge_hex"] + "00"
    require(document["credential_command"] == expected_command, "marker leaked to credential")
    captured = next(e for e in vector["apdu_exchanges"] if e.get("plain_command") == expected_command)
    require(document["credential_response"] == captured["plain_response"], "response differs from capture")
    require(captured["sw"] == "9000", "capture failed")
    container = next(v for t, v, _ in tlvs(bytes.fromhex(vector["vci_objects"]["Card Auth Cert"]["data_hex"])) if t == b"\x53")
    certificate = next(v for t, v, _ in tlvs(container) if t == b"\x70")
    template = next(v for t, v, _ in tlvs(bytes.fromhex(captured["plain_response"])) if t == b"\x7c")
    signature = next(v for t, v, _ in tlvs(template) if t == b"\x82")
    x509.load_der_x509_certificate(certificate).public_key().verify(
        signature, bytes.fromhex(op["challenge_hex"]), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    frames = 0
    for case in document["cases"]:
        request_data, response_data = bytearray(), bytearray()
        complete = False
        error = None
        for index, row in enumerate(case["exchanges"]):
            sequence = index % 3 + 1
            command = packet(row["request"], 1, sequence)
            reply = packet(row["reply"], 0x81, sequence)
            frames += 2
            if command[0] == 0xA5:
                require(not complete and reply == b"\x40", "request acceptance")
                total, offset, size = [int.from_bytes(command[i:i + 2], "little") for i in (1, 3, 5)]
                require(total == len(record) and offset == len(request_data)
                        and size == len(command) - 7, "request multipart fields")
                request_data.extend(command[7:])
                continue
            require(command == b"\x60" and request_data == record, "poll before complete request")
            if complete:
                require(reply == b"\x40", "duplicate terminal result")
            elif reply[0] == 0x82:
                total, offset, size = [int.from_bytes(reply[i:i + 2], "little") for i in (1, 3, 5)]
                require(total == len(bytes.fromhex(captured["plain_response"]))
                        and offset == len(response_data) and size == len(reply) - 7 and size > 0,
                        "response multipart fields")
                response_data.extend(reply[7:])
                complete = len(response_data) == total
            elif reply[0] == 0x8A:
                expected = ("8A23106982" if case["id"] == "credential-rejection" else "8A0200")
                require(reply.hex().upper() == expected, "terminal error/status")
                require(bool(response_data) == (case["id"] == "delivery-failure"), "failure timing")
                error = int.from_bytes(reply[1:3], "little")
                response_data.clear()
                complete = True
            else:
                raise ValueError("unexpected completion reply")
        require(complete and case["error"] == error, "missing completion")
        require(case["result"] == response_data.hex().upper(), "partial response retained")
        if error is None:
            require(case["result"] == captured["plain_response"], "success data")
    return frames


if __name__ == "__main__":
    document = json.loads((ROOT / "worked-examples/crauth/examples.json").read_text())
    print(f"Verified {len(document['cases'])} CRAUTH examples, {verify(document)} frames and captured SM cryptography")
