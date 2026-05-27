#!/usr/bin/env python3
"""Simulate the proposed OSDP PIV Auto flow with real cryptography.

This is a readable protocol demonstration, not an OSDP packet parser. The log
shows representative ACU, PD, and card actions while every cryptographic claim
in the flow is actually computed and verified:

* the ACU configures fixed-width PIV Auto counters and supplemental entropy;
* the PD validates a CVC chain using a loaded trust anchor and an intermediate
  CVC;
* the PD derives a PIV Auto challenge with KMAC256; and
* the card signs the challenge with the card authentication private key.

The fixtures are intentionally reusable demonstration keys copied from
gsa-icam-card-builder. They must not be used for production systems.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Crypto.Hash import KMAC256
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_FIXTURE_DIR = REPO_ROOT / "test-vectors" / "piv-auto-demo"

KMAC_CUSTOMIZATION = b"OSDP-PIV-AUTO-CHALLENGE-v1"
FASCN = bytes.fromhex("D13810D828AB6C10C339E5A1685A08C92ADE0A6184E739C3E7")
UUID = bytes.fromhex("09D49C7EFDD0432EACEA268AE905274C")
DEFAULT_SUPPLEMENTAL_ENTROPY = bytes.fromhex(
    "00112233445566778899AABBCCDDEEFF"
    "102132435465768798A9BACBDCEDFE0F"
)

OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"


class SimulationFailure(RuntimeError):
    """Expected failure raised by negative demonstration modes."""


@dataclass(frozen=True)
class KeyMaterial:
    """PKCS#12 key material used by one simulated party."""

    name: str
    private_key: object
    certificate: x509.Certificate


def encode_len(length: int) -> bytes:
    """Encode the definite BER/DER length used by the compact demo TLVs."""
    if length < 0:
        raise ValueError("negative length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode_tlv(tag: bytes, value: bytes) -> bytes:
    """Build one BER-TLV object."""
    return tag + encode_len(len(value)) + value


def read_len(data: bytes, offset: int) -> tuple[int, int]:
    """Read a definite BER/DER length."""
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite lengths are not used in this demo")
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def read_tlv(data: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, int]:
    """Read one TLV and return tag, value, original encoded TLV, next offset."""
    start = offset
    tag = [data[offset]]
    offset += 1
    if tag[0] & 0x1F == 0x1F:
        while True:
            tag.append(data[offset])
            more = data[offset] & 0x80
            offset += 1
            if not more:
                break
    length, value_offset = read_len(data, offset)
    end = value_offset + length
    return bytes(tag), data[value_offset:end], data[start:end], end


def children(data: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """Decode all child TLVs from a constructed TLV value."""
    out: list[tuple[bytes, bytes, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, tlv, offset = read_tlv(data, offset)
        out.append((tag, value, tlv))
    return out


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OBJECT IDENTIFIER value."""
    parts = [int(part) for part in oid.split(".")]
    encoded = bytearray([parts[0] * 40 + parts[1]])
    for number in parts[2:]:
        stack = [number & 0x7F]
        number >>= 7
        while number:
            stack.append(0x80 | (number & 0x7F))
            number >>= 7
        encoded.extend(reversed(stack))
    return bytes(encoded)


def decode_oid(value: bytes) -> str:
    """Decode an OBJECT IDENTIFIER value for log output and signature checks."""
    first = value[0]
    numbers = [first // 40, first % 40]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            numbers.append(acc)
            acc = 0
    return ".".join(str(number) for number in numbers)


def hexstr(data: bytes) -> str:
    """Return upper-case hex for stable JSON output."""
    return data.hex().upper()


def cert_label(cert: x509.Certificate) -> str:
    """Return a compact certificate subject for log output."""
    return cert.subject.rfc4514_string()


def load_pkcs12(path: Path, name: str) -> KeyMaterial:
    """Load one no-password PKCS#12 fixture."""
    private_key, certificate, _additional = pkcs12.load_key_and_certificates(path.read_bytes(), None)
    if private_key is None or certificate is None:
        raise ValueError(f"{path} does not contain a private key and certificate")
    return KeyMaterial(name=name, private_key=private_key, certificate=certificate)


def ski(cert: x509.Certificate) -> bytes:
    """Return the certificate Subject Key Identifier extension value."""
    return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest


def iin(cert: x509.Certificate) -> bytes:
    """Return the eight-byte selector used by the proposal."""
    return ski(cert)[:8]


def key_algorithm(public_key: object) -> str:
    """Return a readable key algorithm name."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC-{public_key.curve.name}"
    return public_key.__class__.__name__


def make_trust_anchor_record(cert: x509.Certificate) -> bytes:
    """Build the same 7F50 trust-anchor record as make_vci_trust_anchor.py."""
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    body = b"".join(
        [
            encode_tlv(b"\x80", b"\x01"),
            encode_tlv(b"\x42", iin(cert)),
            encode_tlv(b"\x7f\x49", spki),
        ]
    )
    return encode_tlv(b"\x7f\x50", body)


def sign_bytes(private_key: object, data: bytes) -> tuple[str, bytes]:
    """Sign bytes with either RSA/SHA-256 or ECDSA/SHA-256."""
    if isinstance(private_key, rsa.RSAPrivateKey):
        return OID_RSA_SHA256, private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return OID_ECDSA_SHA256, private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise TypeError(f"unsupported private key: {private_key.__class__.__name__}")


def verify_signature(public_key: object, algorithm_oid: str, data: bytes, signature: bytes) -> None:
    """Verify bytes with the public-key algorithm named by the CVC signature."""
    if isinstance(public_key, rsa.RSAPublicKey) and algorithm_oid == OID_RSA_SHA256:
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey) and algorithm_oid == OID_ECDSA_SHA256:
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return
    raise ValueError(f"unsupported signature/public-key combination: {algorithm_oid}")


def make_signature_object(algorithm_oid: str, signature: bytes) -> bytes:
    """Create the proposal's DigitalSignature object.

    The object is DER SEQUENCE { AlgorithmIdentifier, BIT STRING }. RSA includes
    the conventional NULL parameter; ECDSA omits parameters.
    """
    oid_tlv = encode_tlv(b"\x06", encode_oid(algorithm_oid))
    if algorithm_oid == OID_RSA_SHA256:
        alg_id = encode_tlv(b"\x30", oid_tlv + encode_tlv(b"\x05", b""))
    else:
        alg_id = encode_tlv(b"\x30", oid_tlv)
    bit_string = encode_tlv(b"\x03", b"\x00" + signature)
    return encode_tlv(b"\x30", alg_id + bit_string)


def parse_signature_object(value: bytes) -> tuple[str, bytes]:
    """Parse the demo DigitalSignature object."""
    tag, seq_value, _tlv, end = read_tlv(value, 0)
    if tag != b"\x30" or end != len(value):
        raise ValueError("DigitalSignature must be a single SEQUENCE")
    alg_id, bit_string = children(seq_value)[:2]
    alg_oid_child = children(alg_id[1])[0]
    algorithm_oid = decode_oid(alg_oid_child[1])
    if bit_string[0] != b"\x03" or not bit_string[1] or bit_string[1][0] != 0:
        raise ValueError("DigitalSignature BIT STRING is malformed")
    return algorithm_oid, bit_string[1][1:]


def make_demo_cvc(
    *,
    issuer_iin: bytes,
    subject_identifier: bytes,
    role: int,
    subject_cert: x509.Certificate,
    signing_key: object,
) -> bytes:
    """Build a compact 7F21 CVC-like record and sign the child TLVs.

    The proposal's trust-anchor work already moved away from trying to force
    X.509 keys into the SP 800-73 intermediate CVC key object. For this demo the
    public key is carried as DER SubjectPublicKeyInfo in tag 7F49, matching the
    trust-anchor record's key representation.
    """
    spki = subject_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signed_children = b"".join(
        [
            encode_tlv(b"\x5f\x29", b"\x80"),
            encode_tlv(b"\x42", issuer_iin),
            encode_tlv(b"\x5f\x20", subject_identifier),
            encode_tlv(b"\x7f\x49", spki),
            encode_tlv(b"\x5f\x4c", bytes([role])),
        ]
    )
    algorithm_oid, signature = sign_bytes(signing_key, signed_children)
    cvc_body = signed_children + encode_tlv(b"\x5f\x37", make_signature_object(algorithm_oid, signature))
    return encode_tlv(b"\x7f\x21", cvc_body)


def parse_demo_cvc(cvc: bytes) -> dict[str, Any]:
    """Parse the compact demo CVC and preserve its signed byte string."""
    tag, value, _tlv, end = read_tlv(cvc, 0)
    if tag != b"\x7f\x21" or end != len(cvc):
        raise ValueError("CVC must be a single 7F21 object")
    fields: dict[bytes, bytes] = {}
    signed_tlvs = bytearray()
    signature_value = None
    for child_tag, child_value, child_tlv in children(value):
        if child_tag == b"\x5f\x37":
            signature_value = child_value
        else:
            signed_tlvs.extend(child_tlv)
            fields[child_tag] = child_value
    if signature_value is None:
        raise ValueError("CVC is missing 5F37 signature")
    algorithm_oid, signature = parse_signature_object(signature_value)
    public_key = serialization.load_der_public_key(fields[b"\x7f\x49"])
    return {
        "issuer_iin": fields[b"\x42"],
        "subject_identifier": fields[b"\x5f\x20"],
        "role": fields[b"\x5f\x4c"][0],
        "public_key": public_key,
        "algorithm": key_algorithm(public_key),
        "signed_bytes": bytes(signed_tlvs),
        "signature_algorithm_oid": algorithm_oid,
        "signature": signature,
        "length": len(cvc),
    }


def verify_cert_signed_by(child: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify an X.509 certificate signature with its issuer public key."""
    public_key = issuer.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        return
    raise TypeError(f"unsupported issuer key: {public_key.__class__.__name__}")


def fixed_width_template(
    *,
    series_counter: int,
    sequence_counter: int,
    supplemental_entropy: bytes,
) -> bytes:
    """Build the fixed-width KDF input template used by PIV Auto.

    The byte layout is intentionally simple for the demo and mirrors the fields
    made normative in the proposal text:

    magic/version | series | sequence | FASC-N | UUID | key ref | algorithm |
    supplemental entropy
    """
    if len(supplemental_entropy) != 32:
        raise ValueError("supplemental entropy must be exactly 32 bytes")
    return b"OSDP-PIV-AUTO\x01" + b"".join(
        [
            series_counter.to_bytes(4, "little"),
            sequence_counter.to_bytes(4, "little"),
            FASCN,
            UUID,
            b"\x9e",  # PIV card authentication key reference.
            b"\x07",  # RSA 2048, matching SP 800-73 GENERAL AUTHENTICATE P1.
            supplemental_entropy,
        ]
    )


def derive_challenge(sc_session_key: bytes, template: bytes) -> bytes:
    """Derive a 32-byte PIV Auto challenge using KMAC256."""
    kmac = KMAC256.new(key=sc_session_key, data=template, mac_len=32, custom=KMAC_CUSTOMIZATION)
    return kmac.digest()


def sign_piv_challenge(card_auth_key: object, challenge: bytes) -> bytes:
    """Simulate the card's GENERAL AUTHENTICATE private-key operation."""
    if isinstance(card_auth_key, rsa.RSAPrivateKey):
        return card_auth_key.sign(challenge, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(card_auth_key, ec.EllipticCurvePrivateKey):
        return card_auth_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    raise TypeError(f"unsupported card key: {card_auth_key.__class__.__name__}")


def verify_piv_response(card_auth_cert: x509.Certificate, challenge: bytes, signature: bytes) -> None:
    """Verify the simulated card response with the card authentication cert."""
    public_key = card_auth_cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        return
    raise TypeError(f"unsupported card cert key: {public_key.__class__.__name__}")


def chunk_status_payload(payload: bytes, fragment_size: int) -> list[dict[str, Any]]:
    """Represent OSDP 2.2-style multi-part poll response fragments."""
    fragments = []
    for offset in range(0, len(payload), fragment_size):
        chunk = payload[offset : offset + fragment_size]
        fragments.append(
            {
                "reply": "osdp_PIVSTATUSR",
                "reply_code": "0x89",
                "total": len(payload),
                "offset": offset,
                "data_len": len(chunk),
                "data_hex": hexstr(chunk),
            }
        )
    return fragments


def build_status_payload(series_counter: int, sequence_counter: int, signature: bytes) -> bytes:
    """Build the proposed PIVSTATUSR payload before multi-part wrapping."""
    fixed = b"".join(
        [
            b"\x00",  # Result: success.
            b"\x00",  # Detail: none.
            series_counter.to_bytes(4, "little"),
            sequence_counter.to_bytes(4, "little"),
            FASCN,
            UUID,
            b"\x9e",  # Key reference: Card Authentication.
            b"\x07",  # RSA-2048 signature.
            len(signature).to_bytes(2, "little"),
        ]
    )
    return fixed + signature


def run_simulation(args: argparse.Namespace) -> dict[str, Any]:
    """Run the positive flow or one selected negative demonstration."""
    fixture_dir = args.fixture_dir
    root = load_pkcs12(fixture_dir / "source-p12" / "root-ca.p12", "root_ca")
    intermediate_ca = load_pkcs12(
        fixture_dir / "source-p12" / "intermediate-ca-rsa2048.p12",
        "intermediate_ca_loaded_in_pd",
    )
    cvc_signer = load_pkcs12(
        fixture_dir / "source-p12" / "intermediate-cvc-signer-p256.p12",
        "intermediate_cvc_signer",
    )
    card_auth = load_pkcs12(fixture_dir / "source-p12" / "card-auth.p12", "card_authentication")

    sc_session_key = bytes.fromhex(args.sc_key)
    if len(sc_session_key) != 32:
        raise ValueError("--sc-key must be 32 bytes for this KMAC256 demo")
    if args.negative == "factory-key":
        sc_session_key = b"\x00" * 32

    series_counter = args.series_counter
    sequence_counter = args.sequence_counter
    supplemental_entropy = bytes.fromhex(args.supplemental_entropy)
    if args.negative == "duplicate-counter":
        prior_used_counters = {(series_counter, sequence_counter)}
    else:
        prior_used_counters = set()

    now = datetime.now(timezone.utc)
    log: dict[str, Any] = {
        "summary": {
            "status": "running",
            "profile": "PIV Auto demonstration",
            "generated_at": now.isoformat(),
        },
        "fixtures": {
            "source": "test-vectors/piv-auto-demo",
            "warning": "Reusable demonstration keys copied from gsa-icam-card-builder; not production material.",
            "parties": [
                {"name": root.name, "subject": cert_label(root.certificate), "algorithm": key_algorithm(root.certificate.public_key())},
                {
                    "name": intermediate_ca.name,
                    "subject": cert_label(intermediate_ca.certificate),
                    "algorithm": key_algorithm(intermediate_ca.certificate.public_key()),
                },
                {
                    "name": cvc_signer.name,
                    "subject": cert_label(cvc_signer.certificate),
                    "algorithm": key_algorithm(cvc_signer.certificate.public_key()),
                },
                {
                    "name": card_auth.name,
                    "subject": cert_label(card_auth.certificate),
                    "algorithm": key_algorithm(card_auth.certificate.public_key()),
                },
            ],
        },
        "acu_configuration": {
            "command": "osdp_PIVMODE",
            "piv_auto_enabled": True,
            "requires_secure_channel_2": True,
            "factory_keys_in_use": sc_session_key == b"\x00" * 32,
            "series_counter": series_counter,
            "sequence_counter": sequence_counter,
            "supplemental_entropy_hex": hexstr(supplemental_entropy),
            "supplemental_entropy_width_bytes": len(supplemental_entropy),
        },
    }

    if sc_session_key == b"\x00" * 32:
        raise SimulationFailure("PIV Auto rejected: SC 2.0 is using factory/default key material")
    if (series_counter, sequence_counter) in prior_used_counters:
        raise SimulationFailure("PIV Auto rejected: duplicate sequence counter within this series")

    verify_cert_signed_by(intermediate_ca.certificate, root.certificate)
    verify_cert_signed_by(cvc_signer.certificate, intermediate_ca.certificate)
    trust_anchor_record = make_trust_anchor_record(intermediate_ca.certificate)
    intermediate_cvc = make_demo_cvc(
        issuer_iin=iin(intermediate_ca.certificate),
        subject_identifier=iin(cvc_signer.certificate),
        role=0x12,
        subject_cert=cvc_signer.certificate,
        signing_key=intermediate_ca.private_key,
    )
    secure_cvc = make_demo_cvc(
        issuer_iin=iin(cvc_signer.certificate),
        subject_identifier=iin(card_auth.certificate),
        role=0x00,
        subject_cert=card_auth.certificate,
        signing_key=cvc_signer.private_key,
    )

    if args.negative == "wrong-anchor":
        wrong_anchor_cert = root.certificate
        loaded_anchor_iin = iin(wrong_anchor_cert)
        loaded_anchor_key = wrong_anchor_cert.public_key()
    else:
        loaded_anchor_iin = iin(intermediate_ca.certificate)
        loaded_anchor_key = intermediate_ca.certificate.public_key()

    parsed_intermediate = parse_demo_cvc(intermediate_cvc)
    parsed_secure = parse_demo_cvc(secure_cvc)
    if args.negative == "missing-intermediate-cvc":
        raise SimulationFailure("PD cannot validate secure CVC: intermediate CVC evidence is missing")

    if parsed_intermediate["issuer_iin"] != loaded_anchor_iin:
        raise SimulationFailure("PD rejected intermediate CVC: issuer IIN does not match loaded trust anchor")
    verify_signature(
        loaded_anchor_key,
        parsed_intermediate["signature_algorithm_oid"],
        parsed_intermediate["signed_bytes"],
        parsed_intermediate["signature"],
    )
    if parsed_secure["issuer_iin"] != parsed_intermediate["subject_identifier"]:
        raise SimulationFailure("PD rejected secure CVC: issuer IIN does not match intermediate CVC subject")
    verify_signature(
        parsed_intermediate["public_key"],
        parsed_secure["signature_algorithm_oid"],
        parsed_secure["signed_bytes"],
        parsed_secure["signature"],
    )

    template = fixed_width_template(
        series_counter=series_counter,
        sequence_counter=sequence_counter,
        supplemental_entropy=supplemental_entropy,
    )
    challenge = derive_challenge(sc_session_key, template)
    signature = sign_piv_challenge(card_auth.private_key, challenge)
    if args.negative == "tampered-response":
        signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
    try:
        verify_piv_response(card_auth.certificate, challenge, signature)
    except InvalidSignature as exc:
        raise SimulationFailure("ACU rejected signed response: card authentication signature is invalid") from exc

    status_payload = build_status_payload(series_counter, sequence_counter, signature)
    fragments = chunk_status_payload(status_payload, args.fragment_size)

    generated_dir = fixture_dir / "generated"
    generated_dir.mkdir(parents=True, exist_ok=True)
    (generated_dir / "loaded-intermediate-ca-trust-anchor.bin").write_bytes(trust_anchor_record)
    (generated_dir / "intermediate-cvc-7f21.bin").write_bytes(intermediate_cvc)
    (generated_dir / "secure-card-cvc-7f21.bin").write_bytes(secure_cvc)
    (generated_dir / "pivstatusr-payload.bin").write_bytes(status_payload)

    log.update(
        {
            "pd_validation": {
                "loaded_anchor": {
                    "source_certificate": "certs/intermediate-ca-rsa2048.crt",
                    "iin": hexstr(loaded_anchor_iin),
                    "trust_anchor_record_length": len(trust_anchor_record),
                    "algorithm": key_algorithm(loaded_anchor_key),
                },
                "intermediate_cvc": {
                    "present": True,
                    "issuer_iin": hexstr(parsed_intermediate["issuer_iin"]),
                    "subject_identifier": hexstr(parsed_intermediate["subject_identifier"]),
                    "role": f"0x{parsed_intermediate['role']:02X}",
                    "signature_verified_with_loaded_anchor": True,
                    "length": parsed_intermediate["length"],
                },
                "secure_cvc": {
                    "issuer_iin": hexstr(parsed_secure["issuer_iin"]),
                    "subject_identifier": hexstr(parsed_secure["subject_identifier"]),
                    "signature_verified_with_intermediate_cvc": True,
                    "length": parsed_secure["length"],
                },
                "scope": "PD validates only the immediate CVC chain needed to trust the card response.",
            },
            "kdf": {
                "algorithm": "KMAC256",
                "customization": KMAC_CUSTOMIZATION.decode("ascii"),
                "sc_session_key_hex": hexstr(sc_session_key),
                "fixed_template_hex": hexstr(template),
                "challenge_hex": hexstr(challenge),
            },
            "card_operation": {
                "apdu": "GENERAL AUTHENTICATE, key reference 0x9E, RSA-2048",
                "fascn_hex": hexstr(FASCN),
                "uuid": "09d49c7e-fdd0-432e-acea-268ae905274c",
                "signed_response_hex": hexstr(signature),
                "signed_response_length": len(signature),
            },
            "poll_response": {
                "reply": "osdp_PIVSTATUSR",
                "reply_code": "0x89",
                "multi_part_fragment_size": args.fragment_size,
                "payload_length": len(status_payload),
                "fragments": fragments,
            },
            "acu_validation": {
                "x509_path": [
                    {"certificate": "certs/root-ca.crt", "subject": cert_label(root.certificate), "trusted_root": True},
                    {
                        "certificate": "certs/intermediate-ca-rsa2048.crt",
                        "subject": cert_label(intermediate_ca.certificate),
                        "signature_verified_by": "root-ca.crt",
                    },
                    {
                        "certificate": "certs/intermediate-cvc-signer-p256.crt",
                        "subject": cert_label(cvc_signer.certificate),
                        "signature_verified_by": "intermediate-ca-rsa2048.crt",
                    },
                    {
                        "certificate": "certs/card-auth.crt",
                        "subject": cert_label(card_auth.certificate),
                        "signature_verified_by": "deployment PIV certificate path policy",
                        "note": (
                            "The simulated card authentication public key is bound to the PIV Auto "
                            "exchange by the secure card CVC; the ACU still applies its normal PIV "
                            "certificate path, time, policy, and revocation checks separately."
                        ),
                    },
                ],
                "time_policy_revocation_note": (
                    "The ACU, not the PD, is responsible for certificate validity time, policy/EKU, "
                    "and revocation decisions before accepting the establishment result."
                ),
                "card_response_signature_verified": True,
                "counter_uniqueness_checked_by_acu": True,
            },
            "generated_files": {
                "trust_anchor": "test-vectors/piv-auto-demo/generated/loaded-intermediate-ca-trust-anchor.bin",
                "intermediate_cvc": "test-vectors/piv-auto-demo/generated/intermediate-cvc-7f21.bin",
                "secure_cvc": "test-vectors/piv-auto-demo/generated/secure-card-cvc-7f21.bin",
                "pivstatusr_payload": "test-vectors/piv-auto-demo/generated/pivstatusr-payload.bin",
            },
            "result": {"passed": True, "failure_reason": None},
        }
    )
    log["summary"]["status"] = "passed"
    log["summary"]["message"] = "PIV Auto challenge, CVC validation, poll response, and ACU validation completed."
    return log


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    parser.add_argument("--series-counter", type=int, default=7)
    parser.add_argument("--sequence-counter", type=int, default=42)
    parser.add_argument("--fragment-size", type=int, default=96)
    parser.add_argument(
        "--supplemental-entropy",
        default=hexstr(DEFAULT_SUPPLEMENTAL_ENTROPY),
        help="32-byte supplemental entropy as hex; all zeroes are allowed but not recommended",
    )
    parser.add_argument(
        "--sc-key",
        default="C001D00DC001D00DC001D00DC001D00D0123456789ABCDEFFEDCBA9876543210",
        help="32-byte simulated SC 2.0 session key as hex",
    )
    parser.add_argument(
        "--negative",
        choices=["factory-key", "duplicate-counter", "tampered-response", "wrong-anchor", "missing-intermediate-cvc"],
        help="Run one expected failure scenario",
    )
    parser.add_argument("--output", type=Path, help="Optional path to write the JSON log")
    args = parser.parse_args()

    try:
        report = run_simulation(args)
        text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0
    except SimulationFailure as exc:
        report = {
            "summary": {"status": "failed", "message": str(exc)},
            "result": {"passed": False, "failure_reason": str(exc)},
        }
        text = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(text + "\n", encoding="utf-8")
        print(text)
        return 2
    except Exception as exc:  # noqa: BLE001 - command-line diagnostics
        print(json.dumps({"summary": {"status": "error"}, "error": repr(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
