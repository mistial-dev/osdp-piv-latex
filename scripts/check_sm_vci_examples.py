#!/usr/bin/env python3
"""Independent checks for captured OPACITY/SM and example OSDP frames.

Cryptographic equations follow the MIT-0 OpenPhysical verify_vectors.py
in the source capture package. This smaller verifier uses repository fixtures
and does not import the packet simulator.
"""
import argparse
import binascii
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

from validate_vci_chain import children, parse_anchor, parse_cvc, verify_signature

ROOT = Path(__file__).resolve().parents[1]
ANCHOR = ROOT / "test-vectors/vci-trust-anchors/card-2-direct/vci-trust-anchor-record.bin"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def tlvs(data):
    return [(tag, value, raw) for tag, _, value, raw in children(data)]


def cmac(key, data):
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def crypt(key, data, iv=None, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.ECB() if iv is None else modes.CBC(iv))
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(data) + op.finalize()


def unpad(data):
    data = data.rstrip(b"\x00")
    require(data.endswith(b"\x80"), "invalid ISO 7816 padding")
    return data[:-1]


def body(command):
    if len(command) <= 5:
        return b""
    start = 7 if command[4] == 0 else 5
    size = int.from_bytes(command[5:7], "big") if start == 7 else command[4]
    require(start + size <= len(command), "truncated APDU")
    return command[start:start + size]


def verify_capture(vector, anchor=ANCHOR):
    """Recompute trust, ECDH, KDF, cryptogram, MAC chains and plaintext.

    The captures contain single-use private test values. No card is contacted.
    Transport-chain fragments are joined before SM verification.
    """
    h = bytes.fromhex
    op = vector["opacity"]
    raw_cvc = h(op["cvc_raw"])
    cvc = parse_cvc(raw_cvc, "capture")
    ta = parse_anchor(Path(anchor).read_bytes())
    require(cvc["iin"] == ta["iin"], "no matching trust anchor")
    ok, reason = verify_signature(ta["public_key"], cvc["signature_algorithm_oid"],
                                  cvc["signature"], cvc["tbs"])
    require(ok, "CVC signature invalid: " + str(reason))
    suite = vector["card_info"]["cipher_suite_id"]
    require(suite in (0x27, 0x2E), "unsupported suite")
    select = bytes.fromhex(vector["card_info"]["select_response"])
    application = next(value for tag, value, _ in tlvs(select) if tag == b"\x61")
    algorithms_template = next(value for tag, value, _ in tlvs(application) if tag == b"\xac")
    advertised = [value for tag, value, _ in tlvs(algorithms_template) if tag == b"\x80"]
    require(bytes([suite]) in advertised, "SM suite absent from SELECT response")
    curve = ec.SECP256R1() if suite == 0x27 else ec.SECP384R1()
    key_size = 16 if suite == 0x27 else 32
    digest = hashlib.sha256 if suite == 0x27 else hashlib.sha384
    private = ec.derive_private_key(int(op["ephemeral_private_key_d"], 16), curve)
    pub = private.public_key().public_numbers()
    require(pub.x == int(op["ephemeral_public_key_x"], 16)
            and pub.y == int(op["ephemeral_public_key_y"], 16), "ephemeral public key mismatch")
    shared = private.exchange(ec.ECDH(), cvc["public_key"])
    require(shared == h(op["shared_secret_Z"]), "ECDH mismatch")
    identity = hashlib.sha256(raw_cvc).digest()[:8]
    xy = h(op["ephemeral_public_key_x"] + op["ephemeral_public_key_y"])
    nonce = h(op["n_ICC"])
    info = (bytes([4]) + bytes([9 if suite == 0x27 else 13]) * 4
            + b"\x08" + h(op["id_sH"]) + b"\x01" + h(op["cb_H"])
            + b"\x10" + xy[:16] + b"\x08" + identity
            + bytes([len(nonce)]) + nonce + b"\x01" + h(op["cb_ICC"]))
    require(info == h(op["other_info"]), "KDF context mismatch")
    material = b"".join(digest(i.to_bytes(4, "big") + shared + info).digest()
                         for i in range(1, 5))[:4 * key_size]
    keys = [material[i:i + key_size] for i in range(0, len(material), key_size)]
    for key, name in zip(keys, ("sk_cfrm", "sk_mac", "sk_enc", "sk_rmac")):
        require(key == h(op[name]), name + " mismatch")
    auth = cmac(keys[0], b"KC_1_V" + identity + h(op["id_sH"]) + xy)[:16]
    require(auth == h(op["auth_cryptogram"]), "authentication cryptogram mismatch")
    ga = next(e for e in vector["apdu_exchanges"] if e["command"] == op["general_authenticate_command"])
    require(ga["sw"] == "9000", "key establishment status is not success")
    ga_command = h(ga["command"])
    require(ga_command[:4] == bytes([0, 0x87, suite, 4]), "key establishment command header")
    command_template = tlvs(body(ga_command))
    require(len(command_template) == 1 and command_template[0][0] == b"\x7c",
            "key establishment command template")
    command_fields = tlvs(command_template[0][1])
    require(len(command_fields) == 2 and [x[0] for x in command_fields] == [b"\x81", b"\x82"],
            "key establishment command fields")
    require(command_fields[0][1] == h(op["cb_H"]) + h(op["id_sH"]) + b"\x04" + xy
            and command_fields[1][1] == b"", "key establishment host input mismatch")
    require(ga["response"] == op["general_authenticate_response"], "key establishment capture mismatch")
    template = tlvs(h(ga["response"]))
    require(len(template) == 1 and template[0][0] == b"\x7c", "key establishment response template")
    result = tlvs(template[0][1])
    require(len(result) == 1 and result[0][0] == b"\x82", "key establishment response field")
    require(result[0][1] == h(op["cb_ICC"]) + nonce + auth + raw_cvc,
            "CVC/nonce/cryptogram differ from card response")
    count, command_mcv, response_mcv = 1, bytes(16), bytes(16)
    pending = b""
    verified = 0
    active = False
    for exchange in vector["apdu_exchanges"]:
        cmd = h(exchange["command"])
        if exchange is ga:
            active = True
            continue
        if not active:
            continue
        require(exchange["sw"] == "9000", "protected exchange outer status is not success")
        require(cmd[0] in (0x0C, 0x1C), "plaintext command after SM establishment")
        pending += body(cmd)
        if cmd[0] == 0x1C:
            require(exchange["sw"] == "9000" and not exchange["response"], "invalid chain acknowledgement")
            continue
        fields = tlvs(pending)
        pending = b""
        values = {t: v for t, v, _ in fields}
        protected = b"".join(raw for tag, _, raw in fields if tag != b"\x8e")
        command_mcv = cmac(keys[1], command_mcv + cmd[:4] + b"\x80" + bytes(11) + protected)
        require(command_mcv[:8] == values[b"\x8e"], "command MAC mismatch")
        counter = count.to_bytes(16, "big")
        snapshot = exchange.get("sm_state")
        if snapshot:
            require(h(snapshot["counter"]) == counter, "counter mismatch")
            require(h(snapshot["cmd_mcv"]) == command_mcv, "command chaining mismatch")
            require(h(snapshot["resp_mcv"]) == response_mcv, "response chaining mismatch")
        if b"\x87" in values:
            plaintext = unpad(crypt(keys[2], values[b"\x87"][1:], crypt(keys[2], counter), True))
            require(plaintext == body(h(exchange["plain_command"])), "command plaintext mismatch")
        response = tlvs(h(exchange["response"]))
        values = {t: v for t, v, _ in response}
        response_mcv = cmac(keys[3], response_mcv + b"".join(raw for t, _, raw in response if t != b"\x8e"))
        require(response_mcv[:8] == values[b"\x8e"], "response MAC mismatch")
        require(len(values[b"\x99"]) == 2, "missing protected status")
        if b"\x87" in values:
            r_counter = bytes([counter[0] | 0x80]) + counter[1:]
            plaintext = unpad(crypt(keys[2], values[b"\x87"][1:], crypt(keys[2], r_counter), True))
            if exchange.get("plain_response"):
                require(plaintext == h(exchange["plain_response"]), "response plaintext mismatch")
        verified += 1
        count += 1
    require(not pending, "unfinished APDU chain")
    return {"cvc_signature": True, "ecdh_kdf_cryptogram": True,
            "protected_exchanges": verified, "anchor_iin": ta["iin"].hex().upper()}


def packet(data, reply):
    raw = bytes.fromhex(data)
    require(len(raw) >= 8 and raw[0] == 0x53, "packet framing")
    require(raw[1] == (0x81 if reply else 0x01), "packet address")
    require(int.from_bytes(raw[2:4], "little") == len(raw), "packet length")
    require(raw[4] & 0xFC == 4, "CRC-only control expected")
    require(binascii.crc_hqx(raw[:-2], 0x1D0F) == int.from_bytes(raw[-2:], "little"), "packet CRC")
    return raw[4] & 3, raw[5:-2]


def verify_examples(document):
    frames = 0
    for example in document["examples"]:
        vector = None
        sequence = 1
        for exchange in example["exchanges"]:
            seq, request = packet(exchange["request"], False)
            reply_seq, reply = packet(exchange["reply"], True)
            require(seq == sequence == reply_seq, "sequence mismatch")
            sequence = sequence % 3 + 1
            frames += 2
        require(example["exchanges"], "empty example")
        auto_record = bytearray()
        auto_total = None
        for exchange in example["exchanges"]:
            reply = packet(exchange["reply"], True)[1]
            if reply[0] != 0x89:
                continue
            total, offset, size = (int.from_bytes(reply[i:i + 2], "little") for i in (1, 3, 5))
            require(offset == len(auto_record) and size == len(reply) - 7, "Auto fragment sequence")
            require(auto_total in (None, total), "Auto total changed")
            auto_total = total
            auto_record.extend(reply[7:])
        if auto_total is not None:
            require(len(auto_record) == auto_total and auto_total >= 55, "Auto record length")
            signed_length = int.from_bytes(auto_record[53:55], "little")
            trailing = auto_total - 55 - signed_length
            require(trailing in (0, 2), "Auto status-word length")
            require(auto_record[0] != 0 or trailing == 0, "success must omit status word")
            require(auto_record[0] not in (7, 8) or trailing == 0,
                    "local failure or timeout must omit status word")
            if trailing:
                require(auto_record[-2:] != b"\x90\x00" and auto_record[-2] != 0x61,
                        "failure must not carry a successful credential status")
            if auto_record[0] == 6:
                require(auto_record[1] == 0, "Auto rejection detail must be zero")
        if example["id"] == "auto-status-word":
            require(auto_record == bytes([6, 0]) + bytes.fromhex("0100000002000000")
                    + bytes(41) + bytes.fromhex("9A0700006982"), "Auto full status word")
        if example["id"] == "sm-credential-rejection":
            replies = [packet(row["reply"], True)[1] for row in example["exchanges"]]
            require(replies[:4] == [b"\x40", b"\x86\x03", b"\x86\x00", b"\x40"],
                    "credential rejection lifecycle")
            require(replies[4][:5] == bytes.fromhex("8501020101"), "PIN rejection must preserve SM and VCI")
            require(not example["apdus"], "modeled rejection must not claim captured APDUs")
        if example["id"].startswith("pin-expiration-"):
            kind = example["id"].removeprefix("pin-expiration-")
            replies = [packet(row["reply"], True)[1] for row in example["exchanges"]]
            expected = {
                "idle": ["40", "8600", "40", "8600", "40", "860A"],
                "waiting": ["40", "8600", "40", "40", "860A"],
                "boundary": ["40", "8600", "40", "860A"],
                "reuse": ["40", "8600", "40", "8600", "40", "8600", "8602"],
            }
            if kind in expected:
                require(replies == [bytes.fromhex(x) for x in expected[kind]], "expiration completion sequence")
                require(not example["apdus"], "modeled expiration case claims credential APDUs")
            else:
                require(kind == "submitted" and replies[-3:] == [b"\x40", b"\x86\x00", b"\x86\x02"],
                        "submitted VERIFY must finish with its result")
            times = {"idle": [0, 0, 10, 10, 10, 10], "waiting": [0, 0, 0, 0, 10],
                     "boundary": [0, 0, 9, 10], "submitted": [0, 0, 0, 0, 9, 10, 10],
                     "reuse": [0, 0, 1, 1, 2, 2, 10]}
            require([row["time_seconds"] for row in example["exchanges"]] == times[kind], "expiration timing")
            require(example["final_state"] == {"cache_available": False,
                    "pin_verified": kind in ("submitted", "reuse"), "deadline": 10}, "expiration final state")
            require(example["verify_successes"] == {"submitted": 1, "reuse": 2}.get(kind, 0),
                    "unexpected VERIFY completion")
        if example.get("source"):
            path = ROOT / example["source"]
            require(hashlib.sha256(path.read_bytes()).hexdigest() == example["source_sha256"], "source hash mismatch")
            vector = json.loads(path.read_text())
            verify_capture(vector)
            for event in example["apdus"]:
                expected = vector["apdu_exchanges"][event["source_index"]]
                for field in ("command", "response", "sw"):
                    require(event[field] == expected[field], "APDU differs from capture")
            require([e["source_index"] for e in example["apdus"]] == list(range(len(example["apdus"]))),
                    "replay skipped or reordered captured context")
        if example["id"] == "contact-sm":
            _, result = packet(example["exchanges"][-1]["reply"], True)
            require(result[:5] == bytes.fromhex("8501010201"), "contact SM status")
        if example["id"] == "contactless-pairing":
            _, result = packet(example["exchanges"][-1]["reply"], True)
            require(result[:5] == bytes.fromhex("8501020101"), "VCI completion status")
        if example["id"] == "cache-before-card":
            replies = [packet(row["reply"], True)[1] for row in example["exchanges"]]
            require(replies[0:2] == [b"\x40", b"\x86\x00"], "cache lifecycle")
            require(replies[-2:] == [b"\x40", b"\x86\x00"], "verification lifecycle")
        failure = {"auto-pairing-required": (5, 1), "auto-required-sm-empty-store": (2, 1),
                   "auto-cvc-validation-failed": (2, 3), "auto-cryptogram-failed": (2, 4)}
        if example["id"] in failure:
            _, result = packet(example["exchanges"][0]["reply"], True)
            require(result[0] == 0x89 and result[1:7] == bytes.fromhex("370000003700"), "Auto multipart fields")
            require(tuple(result[7:9]) == failure[example["id"]], "Auto result/detail mismatch")
            require(result[9:17] == bytes.fromhex("0100000002000000"), "configured Auto counters")
            require(result[17:58] == bytes(41), "unavailable identity must be zero")
            require(result[58:] == bytes([0x9A if failure[example["id"]][1] == 1 else 0x9E, 7, 0, 0]),
                    "configured key/algorithm and empty signature")
            require(packet(example["exchanges"][1]["reply"], True)[1] == b"\x40", "completion repeated")
        if example["id"].startswith("diagnostic-"):
            require(vector is not None, "diagnostic example requires a source capture")
            exchanges = example["exchanges"]
            require(packet(exchanges[1]["request"], False)[1] == bytes.fromhex("A902"), "diagnostic request")
            require(packet(exchanges[1]["reply"], True)[1] == b"\x40", "diagnostic ACK")
            record = bytearray()
            for exchange in exchanges[2:]:
                require(packet(exchange["request"], False)[1] == b"\x60", "diagnostic requires POLL")
                payload = packet(exchange["reply"], True)[1]
                require(payload[:2] == b"\x85\x02" and len(payload) >= 9, "diagnostic reply type")
                total = int.from_bytes(payload[2:4], "little")
                offset = int.from_bytes(payload[4:6], "little")
                length = int.from_bytes(payload[6:8], "little")
                require(total == 35 and offset == len(record) and length == len(payload) - 8,
                        "diagnostic multipart fields")
                record.extend(payload[8:])
            require(len(record) == 35, "diagnostic incomplete")
            expected = (bytes([3, 4, 1]) + hashlib.sha256(bytes.fromhex(vector["opacity"]["cvc_raw"])).digest()
                        if example["id"] == "diagnostic-cvc-hash" else bytes([2, 1, 0]) + bytes(32))
            require(record == expected, "diagnostic outcome or CVC hash mismatch")
            auto = packet(exchanges[0]["reply"], True)[1]
            require(auto[0] == 0x89 and auto[7:9] == bytes([2, record[1]]), "diagnostic Auto cause mismatch")
            require(not example["apdus"], "diagnostic must not send credential commands")
    return frames


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", type=Path, default=ROOT / "worked-examples/sm-vci/examples.json")
    args = parser.parse_args()
    doc = json.loads(args.file.read_text())
    frames = verify_examples(doc)
    print(f"Verified {len(doc['examples'])} examples and {frames} OSDP frames; captured SM cryptography verified.")


if __name__ == "__main__":
    main()
