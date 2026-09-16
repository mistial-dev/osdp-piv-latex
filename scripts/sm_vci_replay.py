#!/usr/bin/env python3
"""Packet-driven ACU/PD examples backed by existing card captures.

This is a replay harness, not a live-card driver. Captured APDUs retain their
original order and single-use session values. Policy-only cases are labeled.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from pivdata_simulator import decode_frame, frame
from check_sm_vci_examples import ROOT, tlvs, verify_capture

AID = bytes.fromhex("A000000308000010000100")
ACK = b"\x40"


def preparation_result(*, requires_pin, interface, sm_available, pairing_required,
                       validation_failed=False, vci_supported=True):
    """Modeled prerequisite decision; None permits the selected operation.

    This function establishes eligibility, not a successful signature result.
    """
    if validation_failed:
        return (2, 3)
    if requires_pin and interface == 2:
        if not sm_available:
            return (2, 1)
        if not vci_supported:
            return (5, 3)
        if pairing_required:
            return (5, 1)
    return None


def configured_auto_result(*, key_reference, interface, sm_available,
                           pairing_required, vci_supported=True,
                           pin_verified=False, occ_verified=False,
                           validation_failed=False):
    """Check the configured 9A/9E profile before an authentication command."""
    result = preparation_result(requires_pin=key_reference == 0x9A,
                                interface=interface, sm_available=sm_available,
                                pairing_required=pairing_required,
                                vci_supported=vci_supported,
                                validation_failed=validation_failed)
    if result:
        return result
    if key_reference not in (0x9A, 0x9E):
        return (4, 0)
    if key_reference == 0x9A and not (pin_verified or occ_verified):
        return (5, 2)
    return None


class CapturedCard:
    def __init__(self, source):
        self.source = Path(source)
        self.vector = json.loads(self.source.read_text())
        self.evidence = verify_capture(self.vector)
        self.position = 0
        self.events = []

    def through(self, predicate, purpose):
        """Consume a contiguous capture prefix, recording every intervening APDU."""
        rows = self.vector["apdu_exchanges"]
        for index in range(self.position, len(rows)):
            row = rows[index]
            self.events.append({"source_index": index, "purpose": purpose,
                                **{key: row[key] for key in ("description", "command", "response", "sw")}})
            self.position = index + 1
            if predicate(row):
                return row
        raise ValueError("operation absent from remaining capture")

    @staticmethod
    def protected_status(exchange):
        """Read the protected status from the already verified capture."""
        if exchange["sw"] != "9000":
            raise ValueError("captured protected APDU has unsuccessful outer status")
        statuses = [value for tag, value, _ in tlvs(bytes.fromhex(exchange["response"]))
                    if tag == b"\x99"]
        if len(statuses) != 1 or len(statuses[0]) != 2:
            raise ValueError("captured protected APDU has no unique status")
        return statuses[0]


class Peripheral:
    """Bounded implementation of status, pairing and cached-PIN operations.

    Configuration and credential presentation are fixture events. An existing
    synchronized link starts at sequence 1. OSDP SC permission is a test fixture
    precondition, not inferred from unprotected wire traffic.
    """
    def __init__(self, card=None, interface=2, anchors=True, timeout_defaults=(30, 10)):
        if len(timeout_defaults) != 2 or any(not 1 <= n <= 255 for n in timeout_defaults):
            raise ValueError("PIN timeout defaults must be 1 through 255 seconds")
        self.timeout_defaults = timeout_defaults
        self.entry_deadline = None
        self.entry_started = False
        self.entry_timeouts = timeout_defaults
        self.card = card
        self.interface = interface
        self.anchors = anchors
        self.present = False
        self.security = 0
        self.cached_pin = None
        self.pin_verified = False
        self.pending = None
        self.last_packet = self.last_reply = None
        self.last_sequence = None
        self.verifications = 0
        self.pairings = 0
        self.now = 0
        self.expires = None
        self.retain_on_removal = False
        self.preparation_failed = False
        self.pin_policy = None
        self.sm_outcome = self.sm_detail = 0
        self.cvc_hash = None
        self.diagnostic_fragment_size = 16

    def advance(self, seconds):
        if seconds < 0:
            raise ValueError("elapsed time must be nonnegative")
        self.now += seconds
        if self.pending and self.pending[0] == "cache" and self.now >= self.entry_deadline:
            self.pending = ("reply", bytes([0x86, 2 if self.entry_started else 1]))
        if self.expires is not None and self.now >= self.expires:
            self.cached_pin = None
            if self.pending and self.pending[0] == "wait_verify":
                self.pending = ("reply", b"\x86\x0a")

    def complete_acquisition(self):
        """Keypad completion is independent of the next ACU poll."""
        self.advance(0)
        if not self.pending or self.pending[0] != "cache":
            raise ValueError("no acquisition pending")
        self.cached_pin, validity, self.retain_on_removal = self.pending[1]
        self.expires = self.now + validity
        self.pending = ("reply", b"\x86\x00")

    def key_pressed(self):
        """Local keypad event; no PIN digit is sent over OSDP."""
        self.advance(0)
        if not self.pending or self.pending[0] != "cache":
            raise ValueError("no PIN acquisition pending")
        self.entry_started = True
        self.entry_deadline = self.now + self.entry_timeouts[1]

    def present_card(self):
        if self.preparation_failed:
            raise ValueError("failed preparation requires removal or explicit restart")
        self.present = True
        if not self.anchors:
            self.sm_outcome, self.sm_detail = 2, 1
        if self.card and self.anchors:
            self.card.through(lambda e: e["command"] == self.card.vector["opacity"]["general_authenticate_command"],
                              "Captured setup context through SM establishment")
            self.security = 2
            self.pin_policy = bytes.fromhex(self.card.vector["card_info"]["pin_policy_hex"])
            self.sm_outcome, self.sm_detail = 1, 0
            self.cvc_hash = hashlib.sha256(bytes.fromhex(self.card.vector["opacity"]["cvc_raw"])).digest()
            if self.interface == 2 and not self.card.vector["card_info"]["pairing_required"]:
                self.security = 1

    def remove_card(self):
        self.present = False
        self.pin_policy = None
        self.sm_outcome = self.sm_detail = 0
        self.cvc_hash = None
        self.preparation_failed = False
        self.security = 0
        self.pin_verified = False
        if not self.retain_on_removal:
            self.cached_pin = None
        if self.pending and self.pending[0] in ("pair", "diagnostic"):
            self.pending = ("reply", bytes.fromhex("8A2610"))
        elif self.pending and self.pending[0] in ("verify", "submitted"):
            self.pending = ("reply", b"\x86\x04")

    def status(self):
        if not self.present:
            return b"\x85\x01" + bytes(19) + b"\xff\xff\x00"
        if self.preparation_failed:
            return bytes.fromhex("8A2310")
        iin = bytes.fromhex(self.card.vector["opacity"]["cvc"]["iin"]) if self.card and self.security else bytes(8)
        policy = self.pin_policy if self.pin_policy is not None else b"\xff\xff"
        return (bytes([0x85, 0x01, self.interface, self.security, 1 if self.security else 0])
                + iin + iin + policy + bytes([len(AID)]) + AID)

    def fail_sm(self):
        self.security = 0
        self.cached_pin = None
        self.pin_verified = False
        self.preparation_failed = True
        self.sm_outcome, self.sm_detail = 3, 6

    def verification_transport_failure(self):
        if not self.pending or self.pending[0] != "submitted":
            raise ValueError("no submitted VERIFY")
        self.fail_sm()
        self.pending = ("reply", b"\x86\x0b")

    def submit_pending_verify(self):
        """Fixture boundary: stage a captured response for later completion.

        Capture order is preserved. Elapsed time is modeled, not captured.
        """
        if not self.pending or self.pending[0] not in ("verify", "wait_verify"):
            raise ValueError("no verification pending")
        mode = self.pending[1]
        self.advance(0)
        if not self.present:
            result = b"\x86\x04"
        elif self.preparation_failed:
            result = b"\x86\x08"
        elif self.cached_pin is None:
            result = b"\x86\x0a"
        elif (mode == 2 or self.interface == 2) and self.security != 1:
            result = b"\x86\x09"
        else:
            status = b"\x90\x00"
            if self.card:
                if self.cached_pin != bytes.fromhex(self.card.vector["sm_session"]["pin_hex"]):
                    raise ValueError("replay accepts only the captured test PIN")
                exchange = self.card.through(lambda e: e["description"].startswith("VERIFY PIV PIN")
                                  and e["command"].startswith("0C"),
                                  "Captured intervening session context through PIN verification")
                status = self.card.protected_status(exchange)
            self.pending = ("submitted", status)
            return True
        self.pending = ("reply", result)
        return False

    def execute_pending(self):
        if self.pending[0] == "wait_verify" and not self.present:
            return ACK
        if self.pending[0] in ("verify", "wait_verify"):
            self.submit_pending_verify()
        if self.pending[0] == "cache":
            self.complete_acquisition()
        kind, argument = self.pending
        self.pending = None
        if kind == "reply":
            return argument
        if kind == "diagnostic":
            record, offset = argument
            fragment = record[offset:offset + self.diagnostic_fragment_size]
            end = offset + len(fragment)
            if end < len(record):
                self.pending = ("diagnostic", (record, end))
            return b"\x85\x02" + struct.pack("<HHH", len(record), offset, len(fragment)) + fragment
        if kind == "pair":
            if self.preparation_failed:
                return bytes.fromhex("8A2310")
            if self.interface == 2 and self.security == 1:
                return self.status()
            if self.interface != 2 or self.security != 2:
                return bytes.fromhex("8A2310")
            expected = self.card.vector["sm_session"]["pairing_code_ascii"].encode()
            if argument != expected:
                raise ValueError("replay accepts only the captured test pairing code")
            self.pairings += 1
            try:
                exchange = self.card.through(lambda e: e["description"].startswith("VERIFY Pairing Code"), "Commanded pairing")
                status = self.card.protected_status(exchange)
            except TimeoutError:
                self.fail_sm()
                return bytes.fromhex("8A0200")
            if status != b"\x90\x00":
                if status == b"\x63\x00":
                    self.security = 2
                return bytes.fromhex("8A2310") + status
            self.security = 1
            return self.status()
        if kind == "submitted":
            status = argument
            if status != b"\x90\x00":
                if status == b"\x69\x83":
                    return b"\x86\x05"
                if status[0] == 0x63 and status[1] & 0xF0 == 0xC0:
                    self.cached_pin = None
                    self.pin_verified = False
                    return b"\x86\x03"
                return b"\x86\x08"
            self.verifications += 1
            self.pin_verified = True
            return b"\x86\x00"
        raise ValueError("unknown pending operation")

    def exchange(self, packet):
        address, seq, command = decode_frame(packet)
        if address != 1 or seq == 0:
            raise ValueError("examples require PD 1 on an established link")
        if packet == self.last_packet:
            return self.last_reply
        if self.last_sequence is not None and seq != self.last_sequence % 3 + 1:
            raise ValueError("unexpected sequence")
        if command == b"\x60":
            response = self.execute_pending() if self.pending else ACK
        elif command == b"\xa2":
            self.pending = None
            response = ACK
        elif command == bytes.fromhex("AA050000000000"):
            self.cached_pin = self.pending = None
            response = ACK
        elif self.pending:
            response = b"\x41\x09"
        elif command == b"\xa9\x01":
            self.pending = ("reply", self.status())
            response = ACK
        elif command == b"\xa9\x02":
            record = bytes([self.sm_outcome, self.sm_detail, int(self.cvc_hash is not None)])
            record += self.cvc_hash if self.cvc_hash is not None else bytes(32)
            self.pending = ("diagnostic", (record, 0))
            response = ACK
        elif command and command[0] == 0xA9:
            if len(command) != 2:
                response = b"\x41\x02"
            else:
                self.pending = ("reply", bytes.fromhex("8A0500"))
                response = ACK
        elif len(command) == 9 and command[0] == 0xAD:
            self.pending = ("pair", command[1:])
            response = ACK
        elif len(command) == 7 and command[0] == 0xAA:
            mode = command[1]
            flags, validity = command[4], int.from_bytes(command[-2:], "little")
            allowed_flags = 1 if mode == 4 else 2 if mode in (1, 2, 3) else 0
            if flags & ~allowed_flags or (mode != 4 and validity) or (mode == 4 and not validity):
                response = b"\x41\x09"
            elif mode == 0 and command[2:] == bytes(5):
                self.advance(0)
                response = bytes([0x86, int(self.cached_pin is not None) | (int(self.pin_verified) << 1)])
            elif mode == 4 and int.from_bytes(command[-2:], "little"):
                # Local keypad input is injected by the fixture, never an OSDP field.
                pin = bytes.fromhex(self.card.vector["sm_session"]["pin_hex"]) if self.card else b"123456\xff\xff"
                self.pending = ("cache", (pin, int.from_bytes(command[-2:], "little"), bool(command[4] & 1)))
                self.entry_timeouts = tuple(value or default for value, default
                                            in zip(command[2:4], self.timeout_defaults))
                self.entry_started = False
                self.entry_deadline = self.now + self.entry_timeouts[0]
                response = ACK
            elif mode in (2, 3):
                self.advance(0)
                self.pending = (("reply", b"\x86\x0a") if command[4] & 2 and self.cached_pin is None else
                                ("wait_verify" if command[4] & 2 else "verify", mode))
                response = ACK
            elif mode == 5:
                self.cached_pin = self.pending = None
                response = ACK
            else:
                if mode in range(7):
                    raise ValueError("SPE request outside replay scope")
                response = b"\x41\x09"
        elif command and command[0] == 0xAA:
            response = b"\x41\x02"
        else:
            response = b"\x41\x03"
        self.last_packet, self.last_sequence = packet, seq
        self.last_reply = frame(response, seq, reply=True)
        return self.last_reply


class ACU:
    def __init__(self, pd):
        self.pd = pd
        self.sequence = 1
        self.exchanges = []
        self.status_type = None
        self.diagnostic = bytearray()

    def send(self, payload, note):
        request = frame(payload, self.sequence)
        response = self.pd.exchange(request)
        self.exchanges.append({"time_seconds": self.pd.now, "request": request.hex(" ").upper(),
                               "reply": response.hex(" ").upper(), "notes": note})
        self.sequence = self.sequence % 3 + 1
        reply = decode_frame(response)[2]
        if reply == ACK:
            if payload[:1] == b"\xa9" and len(payload) == 2:
                self.status_type = payload[1]
                self.diagnostic.clear()
            elif payload[:1] == b"\xad":
                self.status_type = 1
            elif payload == b"\xa2":
                self.status_type = None
                self.diagnostic.clear()
        elif reply[:1] == b"\x8a":
            self.status_type = None
            self.diagnostic.clear()
        elif reply[:1] == b"\x85":
            try:
                if len(reply) < 2 or reply[1] not in (1, 2):
                    raise ValueError("unknown CARDSTATUSR type")
                if reply[1] != self.status_type:
                    raise ValueError("CARDSTATUSR type does not match request")
                if reply[1] == 1:
                    if len(reply) < 24 or len(reply) != 24 + reply[23]:
                        raise ValueError("invalid standard status length")
                    self.status_type = None
                else:
                    if len(reply) < 9:
                        raise ValueError("truncated diagnostic fragment")
                    total, offset, count = struct.unpack("<HHH", reply[2:8])
                    if total != 35 or offset != len(self.diagnostic) or count != len(reply) - 8 or offset + count > total:
                        raise ValueError("invalid diagnostic fragment")
                    self.diagnostic.extend(reply[8:])
                    if len(self.diagnostic) == total:
                        self.status_type = None
            except ValueError:
                self.diagnostic.clear()
                raise
        return reply


def failure_status(result, detail, key_reference=0x9A, status_word=b""):
    if len(status_word) not in (0, 2):
        raise ValueError("status word must be absent or two bytes")
    if status_word == b"\x90\x00" or status_word[:1] == b"\x61":
        raise ValueError("failure status cannot carry a successful credential status")
    # Configured counters/key remain available even before a challenge exists.
    body = (bytes([result, detail]) + struct.pack("<II", 1, 2) + bytes(25 + 16)
            + bytes([key_reference, 0x07]) + b"\x00\x00" + status_word)
    return b"\x89" + struct.pack("<HHH", len(body), 0, len(body)) + body


def example(name, source, interface, cache=False):
    card = CapturedCard(ROOT / source)
    pd = Peripheral(card, interface)
    acu = ACU(pd)
    if cache:
        acu.send(bytes.fromhex("AA040000003C00"), "Collect a PIN locally; cache for 0x003C seconds.")
        acu.send(b"\x60", "Collection completes before card presentation.")
    pd.present_card()
    acu.send(bytes.fromhex("A901"), "Read current state after automatic credential preparation.")
    acu.send(b"\x60", "Return the completed card-status query.")
    if interface == 2:
        acu.send(b"\xad" + card.vector["sm_session"]["pairing_code_ascii"].encode(), "Submit the captured pairing code.")
        acu.send(b"\x60", "Pairing completes; SM and VCI are available.")
    if cache:
        acu.send(bytes.fromhex("AA020000000000"), "Verify the cached PIN over established VCI.")
        acu.send(b"\x60", "Report the captured successful PIN verification.")
    return {"id": name, "coverage": "Captured card APDUs and verified cryptography; modeled OSDP lifecycle",
            "source": source, "source_sha256": hashlib.sha256(card.source.read_bytes()).hexdigest(),
            "crypto_checks": card.evidence, "exchanges": acu.exchanges, "apdus": card.events}


def expiration_examples():
    examples = []
    for case in ("idle", "waiting", "boundary", "submitted", "reuse"):
        source = "test-vectors/vci-cvc-corpus/vci-contactless-card01/source-vector.json"
        card = CapturedCard(ROOT / source) if case == "submitted" else None
        pd = Peripheral(card, interface=2 if card else 1)
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000A00"), "Acquire a PIN; Cache Validity is 0x000A seconds.")
        pd.complete_acquisition()
        acu.send(b"\x60", "PIN acquisition completed at t=0; cache deadline is t=10 seconds.")
        timeline = [{"time": 0, "event": "PIN acquisition completes; deadline is 10 seconds."}]
        if case == "waiting":
            acu.send(bytes.fromhex("AA030000020000"), "Arm cached-PIN verification for credential presentation.")
            acu.send(b"\x60", "No credential is present; the request remains pending.")
            pd.advance(10)
            acu.send(b"\x60", "Cache expires while waiting: no cached PIN.")
        elif case == "idle":
            pd.advance(10)
            acu.send(b"\x60", "Idle expiration creates no completion reply.")
            acu.send(bytes.fromhex("AA000000000000"), "Report empty cache and no PIN verification.")
            pd.present_card()
            acu.send(bytes.fromhex("AA030000000000"), "Request verification using the expired cache.")
            acu.send(b"\x60", "No cached PIN; no VERIFY is submitted.")
        else:
            pd.present_card()
            if card:
                acu.send(b"\xad00000002", "Supply the captured pairing code after SM preparation.")
                acu.send(b"\x60", "SM and VCI are available.")
            if case == "reuse":
                for _ in range(2):
                    pd.advance(1)
                    acu.send(bytes.fromhex("AA030000000000"), "Explicit contact verification using the same cached PIN.")
                    acu.send(b"\x60", "Modeled credential success; deadline remains t=10.")
                pd.advance(8)
                acu.send(bytes.fromhex("AA000000000000"), "Cache expired; credential PIN verification remains valid.")
            else:
                pd.advance(9)
                acu.send(bytes.fromhex("AA020000000000" if card else "AA030000000000"),
                         "Accept verification at t=9, before the cache deadline.")
                if case == "submitted":
                    pd.submit_pending_verify()
                    timeline.append({"time": 9, "event": "VERIFY submitted before expiration; response delivery is modeled as delayed."})
                pd.advance(1)
                acu.send(b"\x60", "Return credential success after submission." if card
                         else "Deadline reached before submission: no cached PIN.")
                if card:
                    acu.send(bytes.fromhex("AA000000000000"), "Empty cache; credential PIN verified.")
        timeline.append({"time": 10, "event": "Cache expires and is erased."})
        item = {"id": "pin-expiration-" + case,
                "coverage": "Modeled timing and PIN state; " + ("replayed captured VERIFY success" if card else "no credential APDU capture claimed"),
                "timeline": timeline, "exchanges": acu.exchanges,
                "apdus": card.events if card else [], "verify_successes": pd.verifications,
                "final_state": {"cache_available": pd.cached_pin is not None,
                                "pin_verified": pd.pin_verified, "deadline": pd.expires}}
        if card:
            item.update(source=source, source_sha256=hashlib.sha256(card.source.read_bytes()).hexdigest())
        examples.append(item)
    pd = Peripheral()
    acu = ACU(pd)
    logical = failure_status(6, 0, status_word=bytes.fromhex("6982"))[7:]
    for offset, fragment in ((0, logical[:56]), (56, logical[56:])):
        pd.pending = ("reply", b"\x89" + struct.pack("<HHH", len(logical), offset, len(fragment)) + fragment)
        acu.send(b"\x60", "PIV Auto credential rejection; SW1/SW2 cross the fragment boundary.")
    examples.append({"id": "auto-status-word", "coverage": "Modeled credential rejection and multipart status word",
                     "exchanges": acu.exchanges, "apdus": []})
    pd = Peripheral(interface=2)
    pd.present, pd.security = True, 1
    pd.sm_outcome, pd.sm_detail = 1, 0
    pd.cached_pin, pd.expires = b"123456\xff\xff", 60
    acu = ACU(pd)
    acu.send(bytes.fromhex("AA020000000000"), "Verify a cached PIN over an established VCI; initial state is modeled.")
    pd.pending = ("submitted", bytes.fromhex("63C2"))
    acu.send(b"\x60", "Report PIN mismatch; the credential's modeled protected status is 0x63C2.")
    acu.send(bytes.fromhex("AA000000000000"), "Cache erased and PIN-verification state cleared after PIN mismatch.")
    acu.send(bytes.fromhex("A901"), "Read credential status after ordinary rejection.")
    acu.send(b"\x60", "SM and VCI remain established.")
    examples.append({"id": "sm-credential-rejection", "coverage": "Modeled authenticated credential rejection, no failure capture claimed",
                     "exchanges": acu.exchanges, "apdus": []})
    return examples


def generate():
    corpus = "test-vectors/vci-cvc-corpus/"
    examples = [example("contact-sm", corpus + "vci-vectors-card01/source-vector.json", 1),
                example("contactless-pairing", corpus + "vci-contactless-card01/source-vector.json", 2),
                example("cache-before-card", corpus + "vci-contactless-card01/source-vector.json", 2, True)]
    for name, result, detail in (("auto-pairing-required", 5, 1), ("auto-required-sm-empty-store", 2, 1),
                                 ("auto-cvc-validation-failed", 2, 3), ("auto-cryptogram-failed", 2, 4)):
        pd = Peripheral()
        pd.pending = ("reply", failure_status(result, detail, 0x9A if detail == 1 else 0x9E))
        acu = ACU(pd)
        acu.send(b"\x60", "Terminal PIV Auto result for the modeled preparation outcome.")
        acu.send(b"\x60", "No repeated completion while the same card remains presented.")
        examples.append({"id": name, "coverage": "Modeled result encoding; no captured failure claimed",
                         "exchanges": acu.exchanges, "apdus": []})
    for with_hash in (False, True):
        pd = Peripheral()
        pd.present = True
        pd.sm_outcome, pd.sm_detail = (3, 4) if with_hash else (2, 1)
        pd.preparation_failed = with_hash
        source = ROOT / (corpus + "vci-contactless-card01/source-vector.json")
        vector = json.loads(source.read_text())
        if with_hash:
            pd.cvc_hash = hashlib.sha256(bytes.fromhex(vector["opacity"]["cvc_raw"])).digest()
        pd.pending = ("reply", failure_status(2, pd.sm_detail))
        acu = ACU(pd)
        acu.send(b"\x60", "PIV Auto terminates: cryptogram invalid." if with_hash
                 else "PIV Auto terminates: trust store empty.")
        acu.send(bytes.fromhex("A902"), "Request retained SM diagnostics; no credential command is sent.")
        while pd.pending:
            acu.send(b"\x60", "Read the next diagnostic fragment.")
        examples.append({"id": "diagnostic-cvc-hash" if with_hash else "diagnostic-empty-store",
                         "coverage": "Modeled failure and diagnostic exchange; CVC hash uses captured credential bytes",
                         "source": str(source.relative_to(ROOT)),
                         "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                         "exchanges": acu.exchanges, "apdus": []})
    examples.extend(expiration_examples())
    return {"description": "These examples omit OSDP Secure Channel for clarity.",
            "link": "PD address 0x01; CRC; established link starts at sequence 0x01.",
            "test_precondition": "OSDP SC authorization is assumed only inside this test harness.",
            "examples": examples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(generate(), indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
