#!/usr/bin/env python3
"""Bounded CRAUTH framing model using an existing credential capture."""
import json
import struct
from pathlib import Path

from pivdata_simulator import decode_frame, frame

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "test-vectors/vci-cvc-corpus/vci-contactless-card04/source-vector.json"
OUTPUT = ROOT / "worked-examples/crauth/examples.json"


def request_format(first_data):
    if not first_data:
        raise ValueError("first fragment must contain data")
    return "3.0" if first_data[0] == 0xFF else "2.2"


def multipart(code, data, offset, count):
    chunk = data[offset:offset + count]
    return bytes([code]) + struct.pack("<HHH", len(data), offset, len(chunk)) + chunk


class Peripheral:
    """New-format-only PD. Credential execution is a checked fixture lookup."""
    def __init__(self, expected, response, failure=None, fail_after_data=False):
        self.expected, self.response = expected, response
        self.failure, self.fail_after_data = failure, fail_after_data
        self.data = bytearray()
        self.total = None
        self.ready = False
        self.offset = 0
        self.credential_calls = 0
        self.last_packet = self.last_reply = None
        self.last_sequence = None

    def exchange(self, packet):
        address, sequence, payload = decode_frame(packet)
        if address != 1:
            raise ValueError("wrong PD address")
        if sequence and packet == self.last_packet:
            return self.last_reply
        if self.last_sequence is not None and sequence != self.last_sequence % 3 + 1:
            raise ValueError("unexpected sequence")
        result = self.command(payload)
        self.last_packet, self.last_sequence = packet, sequence
        self.last_reply = frame(result, sequence, reply=True)
        return self.last_reply

    def command(self, payload):
        if payload == b"\xa2":
            self.data.clear()
            self.total, self.ready = None, False
            self.offset = 0
            return b"\x40"
        if payload[:1] == b"\xa5":
            if self.ready:
                return b"\x41\x09"
            if len(payload) < 8:
                return b"\x41\x02"
            total, offset, count = struct.unpack("<HHH", payload[1:7])
            if (count != len(payload) - 7 or offset != len(self.data)
                    or total < 3 or offset + count > total
                    or self.total not in (None, total)):
                self.data.clear()
                self.total = None
                return b"\x41\x09"
            if self.total is None and request_format(payload[7:]) != "3.0":
                return b"\x41\x09"
            self.total = total
            self.data.extend(payload[7:])
            if len(self.data) == total:
                self.ready = True
                if bytes(self.data) != self.expected:
                    self.failure = bytes.fromhex("8A0500")
                else:
                    self.credential_calls += 1
            return b"\x40"
        if payload == b"\x60":
            if not self.ready:
                return b"\x40"
            if self.failure and (not self.fail_after_data or self.offset):
                self.ready = False
                return self.failure
            reply = multipart(0x82, self.response, self.offset, 40)
            self.offset += len(reply) - 7
            if self.offset == len(self.response):
                self.ready = False
            return reply
        return b"\x41\x03"


class Controller:
    def __init__(self):
        self.data = bytearray()
        self.total = None
        self.done = False
        self.error = None

    def receive(self, payload):
        if payload == b"\x40":
            return
        if self.done:
            raise ValueError("reply after completion")
        if payload[:1] == b"\x8a" and len(payload) in (3, 5):
            self.data.clear()
            self.error = int.from_bytes(payload[1:3], "little")
            self.done = True
            return
        if payload[:1] != b"\x82" or len(payload) < 7:
            raise ValueError("unexpected reply")
        total, offset, size = struct.unpack("<HHH", payload[1:7])
        if (size != len(payload) - 7 or offset != len(self.data)
                or offset + size > total or self.total not in (None, total)):
            raise ValueError("invalid response fragment")
        self.total = total
        self.data.extend(payload[7:])
        self.done = len(self.data) == total


def generate():
    source = json.loads((ROOT / SOURCE).read_text())
    signing = source["signing_operations"]["cak"]
    record = bytes.fromhex("FF119E" + signing["challenge_hex"])
    exchange = next(e for e in source["apdu_exchanges"]
                    if e["description"] == "GENERAL AUTHENTICATE Card Authentication Key (0x9E)")
    response = bytes.fromhex(exchange["plain_response"])
    cases = []
    for name, failure, after in (("captured-success", None, False),
                                 ("credential-rejection", bytes.fromhex("8A23106982"), False),
                                 ("delivery-failure", bytes.fromhex("8A0200"), True)):
        pd = Peripheral(record, response, failure, after)
        acu = Controller()
        rows = []
        sequence = 1

        def send(payload):
            nonlocal sequence
            request = frame(payload, sequence)
            reply = pd.exchange(request)
            acu.receive(decode_frame(reply)[2])
            rows.append({"request": request.hex(" ").upper(), "reply": reply.hex(" ").upper()})
            sequence = sequence % 3 + 1

        send(multipart(0xA5, record, 0, 1))
        send(multipart(0xA5, record, 1, len(record) - 1))
        while not acu.done:
            send(b"\x60")
        send(b"\x60")
        cases.append({"id": name, "modeled_failure": failure is not None,
                      "exchanges": rows, "result": bytes(acu.data).hex().upper(),
                      "error": acu.error})
    return {"source": SOURCE, "limitation": "Examples omit OSDP Secure Channel for clarity. "
            "Credential SM is assumed established as in the capture. Failure outcomes are modeled.",
            "record": record.hex().upper(), "credential_command": exchange["plain_command"],
            "credential_response": exchange["plain_response"], "cases": cases}


if __name__ == "__main__":
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(generate(), indent=2) + "\n")
