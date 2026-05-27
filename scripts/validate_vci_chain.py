#!/usr/bin/env python3
"""Validate an OSDP VCI CVC chain and report PD/ACU responsibilities as JSON.

The JSON is ordered for human review. The first section says whether validation
passed and which path was used; the later sections preserve the lower-level
details needed for test automation and proposal review.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID


MAX_RECORD_LEN = 0x0240
OID_EC_P256 = "1.2.840.10045.3.1.7"
OID_EC_P384 = "1.3.132.0.34"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_SHA384 = "1.2.840.113549.1.1.12"
OID_PIV_CONTENT_SIGNING_EKU = "2.16.840.1.101.3.6.7"
OID_PIVI_CONTENT_SIGNING_EKU = "2.16.840.1.101.3.8.7"

CHECK_DESCRIPTIONS = {
    "secure_cvc_iin_matches_anchor_iin": "Secure messaging CVC tag 42 matches the loaded trust anchor IIN.",
    "secure_cvc_signature_with_anchor": "Secure messaging CVC signature verifies with the loaded trust anchor public key.",
    "5fc122_present": "Secure Messaging Certificate Signer object 5FC122 was supplied for intermediate validation.",
    "intermediate_cvc_present": "5FC122 contains an Intermediate CVC.",
    "secure_cvc_iin_matches_intermediate_subject_identifier": (
        "Secure messaging CVC tag 42 matches the Intermediate CVC subject identifier tag 5F20."
    ),
    "intermediate_role_is_12": "Intermediate CVC role identifier tag 5F4C is 0x12.",
    "intermediate_iin_matches_anchor_iin": "Intermediate CVC tag 42 matches the loaded trust anchor IIN.",
    "intermediate_cvc_signature_with_anchor": "Intermediate CVC signature verifies with the loaded trust anchor public key.",
    "secure_cvc_signature_with_intermediate": "Secure messaging CVC signature verifies with the Intermediate CVC public key.",
}


class TlvError(ValueError):
    pass


def read_len(data: bytes, offset: int) -> tuple[int, int]:
    """Read a BER definite length and return (length, value_offset)."""
    if offset >= len(data):
        raise TlvError("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0 or offset + count > len(data):
        raise TlvError("invalid long-form length")
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def read_tlv(data: bytes, offset: int = 0) -> tuple[bytes, int, bytes, bytes, int]:
    """Read one BER-TLV object.

    The returned tuple includes both the decoded value and the original TLV
    bytes. CVC signature verification needs the original encoded child TLVs for
    the to-be-signed byte string.
    """
    start = offset
    if offset >= len(data):
        raise TlvError("missing tag")
    tag = [data[offset]]
    offset += 1
    if tag[0] & 0x1F == 0x1F:
        while True:
            if offset >= len(data):
                raise TlvError("unterminated high-tag-number tag")
            tag.append(data[offset])
            more = data[offset] & 0x80
            offset += 1
            if not more:
                break
    length, value_offset = read_len(data, offset)
    end = value_offset + length
    if end > len(data):
        raise TlvError("TLV length exceeds input")
    return bytes(tag), length, data[value_offset:end], data[start:end], end


def children(data: bytes) -> list[tuple[bytes, int, bytes, bytes]]:
    """Decode all child TLVs from a constructed value."""
    out: list[tuple[bytes, int, bytes, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, length, value, tlv, offset = read_tlv(data, offset)
        out.append((tag, length, value, tlv))
    return out


def decode_oid(value: bytes) -> str:
    """Decode an ASN.1 OBJECT IDENTIFIER value into dotted decimal form."""
    if not value:
        raise ValueError("empty OID")
    first = value[0]
    nums = [first // 40, first % 40]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            nums.append(acc)
            acc = 0
    if acc:
        raise ValueError("unterminated OID")
    return ".".join(str(n) for n in nums)


def load_blob(value: str) -> bytes:
    """Load a binary file, a hex text file, or an inline hex string."""
    path = Path(value)
    if path.exists():
        data = path.read_bytes()
        stripped = re.sub(rb"\s+", b"", data)
        if stripped and re.fullmatch(rb"[0-9A-Fa-f]+", stripped) and len(stripped) % 2 == 0:
            return bytes.fromhex(stripped.decode("ascii"))
        return data
    stripped_text = re.sub(r"\s+", "", value)
    if re.fullmatch(r"[0-9A-Fa-f]+", stripped_text) and len(stripped_text) % 2 == 0:
        return bytes.fromhex(stripped_text)
    raise FileNotFoundError(f"not a file or hex string: {value}")


def key_description(public_key: object) -> str:
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA-{public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC-{public_key.curve.name}"
    return public_key.__class__.__name__


def parse_anchor(data: bytes) -> dict[str, Any]:
    """Parse the OSDP-defined 7F50 VCI trust anchor record."""
    if len(data) > MAX_RECORD_LEN:
        raise ValueError(f"anchor record is {len(data)} bytes, maximum is {MAX_RECORD_LEN}")
    tag, _, value, _, end = read_tlv(data, 0)
    if end != len(data) or tag != b"\x7f\x50":
        raise ValueError("anchor must be a single 7F50 trust anchor record")
    fields = {tag.hex().upper(): value for tag, _, value, _ in children(value)}
    if fields.get("80") != b"\x01":
        raise ValueError("unsupported trust anchor record profile")
    iin = fields.get("42")
    spki = fields.get("7F49")
    if iin is None or len(iin) != 8:
        raise ValueError("trust anchor record missing 8-byte tag 42 IIN")
    if spki is None:
        raise ValueError("trust anchor record missing tag 7F49 SubjectPublicKeyInfo")
    public_key = serialization.load_der_public_key(spki)
    return {
        "iin": iin,
        "spki": spki,
        "public_key": public_key,
        "algorithm": key_description(public_key),
        "record_length": len(data),
        "spki_length": len(spki),
    }


def parse_signature(sig_value: bytes) -> dict[str, Any]:
    """Parse the CVC DigitalSignature object.

    The proposal's CVC signature object carries an AlgorithmIdentifier and a BIT
    STRING signature. The signature bytes are returned without the BIT STRING
    unused-bits prefix.
    """
    tag, _, seq_value, _, end = read_tlv(sig_value, 0)
    if tag != b"\x30" or end != len(sig_value):
        raise ValueError("DigitalSignature is not a DER SEQUENCE")
    seq_children = children(seq_value)
    if len(seq_children) != 2:
        raise ValueError("DigitalSignature must contain AlgorithmIdentifier and BIT STRING")
    alg_tag, _, alg_value, _ = seq_children[0]
    bit_tag, _, bit_value, _ = seq_children[1]
    if alg_tag != b"\x30" or bit_tag != b"\x03":
        raise ValueError("invalid DigitalSignature structure")
    alg_children = children(alg_value)
    if not alg_children or alg_children[0][0] != b"\x06":
        raise ValueError("AlgorithmIdentifier missing algorithm OID")
    if not bit_value or bit_value[0] != 0:
        raise ValueError("signature BIT STRING must have zero unused bits")
    return {"algorithm_oid": decode_oid(alg_children[0][2]), "signature": bit_value[1:]}


def parse_public_key_object(value: bytes) -> dict[str, Any]:
    """Parse the CVC EC public-key object used by current secure CVCs."""
    fields = {tag.hex().upper(): field_value for tag, _, field_value, _ in children(value)}
    oid_value = fields.get("06")
    point = fields.get("86")
    if oid_value is None or point is None:
        raise ValueError("CVC public key object missing OID or public key point")
    curve_oid = decode_oid(oid_value)
    if curve_oid == OID_EC_P256:
        curve: ec.EllipticCurve = ec.SECP256R1()
    elif curve_oid == OID_EC_P384:
        curve = ec.SECP384R1()
    else:
        raise ValueError(f"unsupported CVC curve OID: {curve_oid}")
    return {
        "curve_oid": curve_oid,
        "point": point,
        "public_key": ec.EllipticCurvePublicKey.from_encoded_point(curve, point),
    }


def parse_cvc(data: bytes, label: str) -> dict[str, Any]:
    """Parse a 7F21 CVC and build the exact to-be-signed byte string."""
    tag, _, value, tlv, end = read_tlv(data, 0)
    if tag != b"\x7f\x21" or end != len(data):
        raise ValueError(f"{label} must be a single 7F21 CVC")
    parsed_children = children(value)
    fields = {tag.hex().upper(): field_value for tag, _, field_value, _ in parsed_children}
    tbs = b"".join(tlv for tag, _, _, tlv in parsed_children if tag != b"\x5f\x37")
    if "5F37" not in fields:
        raise ValueError(f"{label} missing DigitalSignature object")
    public_key_object = parse_public_key_object(fields["7F49"])
    signature = parse_signature(fields["5F37"])
    return {
        "label": label,
        "raw": data,
        "tbs": tbs,
        "profile": fields.get("5F29", b"").hex().upper(),
        "iin": fields.get("42", b""),
        "subject_identifier": fields.get("5F20", b""),
        "role": fields.get("5F4C", b""),
        "public_key": public_key_object["public_key"],
        "public_key_curve_oid": public_key_object["curve_oid"],
        "signature_algorithm_oid": signature["algorithm_oid"],
        "signature": signature["signature"],
        "length": len(data),
    }


def verify_signature(public_key: object, algorithm_oid: str, signature: bytes, tbs: bytes) -> tuple[bool, str | None]:
    """Verify a CVC or Intermediate CVC signature with RSA or ECDSA."""
    try:
        if algorithm_oid == OID_ECDSA_SHA256:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False, "ECDSA signature requires EC public key"
            public_key.verify(signature, tbs, ec.ECDSA(hashes.SHA256()))
        elif algorithm_oid == OID_ECDSA_SHA384:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False, "ECDSA signature requires EC public key"
            public_key.verify(signature, tbs, ec.ECDSA(hashes.SHA384()))
        elif algorithm_oid == OID_RSA_SHA256:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "RSA signature requires RSA public key"
            public_key.verify(signature, tbs, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm_oid == OID_RSA_SHA384:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return False, "RSA signature requires RSA public key"
            public_key.verify(signature, tbs, padding.PKCS1v15(), hashes.SHA384())
        else:
            return False, f"unsupported signature algorithm OID: {algorithm_oid}"
        return True, None
    except InvalidSignature:
        return False, "signature verification failed"


def parse_smcs(data: bytes) -> dict[str, Any]:
    """Parse the Secure Messaging Certificate Signer object.

    The input may be the complete inner tag 53 object or just its value. Tag 70
    contains the X.509 content-signing certificate. Some card data stores that
    certificate compressed, so the parser tries both raw DER and gzip-expanded
    DER. Tag 7F21, when present, is the Intermediate CVC used by the PD.
    """
    tag, _, value, _, end = read_tlv(data, 0)
    if tag == b"\x53":
        if end != len(data):
            raise ValueError("5FC122 data has trailing bytes after 53 object")
        body = value
    else:
        body = data
    cert_der = None
    cert_info = None
    intermediate = None
    for child_tag, _, child_value, child_tlv in children(body):
        if child_tag == b"\x70":
            cert_der = child_value
        elif child_tag == b"\x71":
            cert_info = child_value
        elif child_tag == b"\x7f\x21":
            intermediate = child_tlv
    cert = None
    if cert_der is not None:
        candidates = [cert_der]
        try:
            candidates.append(gzip.decompress(cert_der))
        except Exception:  # noqa: BLE001 - try DER next
            pass
        for candidate in candidates:
            try:
                cert = x509.load_der_x509_certificate(candidate)
                cert_der = candidate
                break
            except Exception:  # noqa: BLE001 - try next candidate
                continue
        if cert is None:
            raise ValueError("unable to parse X.509 certificate in 5FC122 tag 70")
    return {
        "certificate": cert,
        "certificate_der": cert_der,
        "cert_info": cert_info,
        "intermediate_cvc": parse_cvc(intermediate, "intermediate_cvc") if intermediate else None,
        "intermediate_raw": intermediate,
        "length": len(data),
    }


def load_pem_certs(path: Path) -> list[x509.Certificate]:
    """Load one DER certificate or a PEM file containing one or more certs."""
    data = path.read_bytes()
    certs = []
    for match in re.finditer(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        data,
        flags=re.DOTALL,
    ):
        certs.append(x509.load_pem_x509_certificate(match.group(0)))
    if certs:
        return certs
    return [x509.load_der_x509_certificate(data)]


def cert_ski(cert: x509.Certificate) -> bytes | None:
    """Return the Subject Key Identifier extension, if present."""
    try:
        return cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    except x509.ExtensionNotFound:
        return None


def cert_eku_oids(cert: x509.Certificate) -> list[str]:
    """Return EKU OIDs as dotted strings."""
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        return [oid.dotted_string for oid in eku]
    except x509.ExtensionNotFound:
        return []


def cert_policy_oids(cert: x509.Certificate) -> list[str]:
    """Return certificate policy OIDs as dotted strings."""
    try:
        policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
        return [policy.policy_identifier.dotted_string for policy in policies]
    except x509.ExtensionNotFound:
        return []


def parse_validation_time(value: str | None) -> datetime | None:
    """Parse optional ISO-8601 validation time and normalize it to UTC."""
    if value is None:
        return None
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> tuple[bool, str | None]:
    """Perform the simple issuer-signature check used in the ACU report."""
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        else:
            return False, f"unsupported issuer key type: {public_key.__class__.__name__}"
        return True, None
    except InvalidSignature:
        return False, "certificate signature verification failed"


def acu_validation(
    anchor: dict[str, Any],
    smcs: dict[str, Any] | None,
    ca_bundle: Path | None,
    validation_time: datetime | None,
) -> dict[str, Any]:
    """Report the full validation duties that belong to the ACU.

    This script can demonstrate a few ACU checks when the inputs are supplied,
    but it deliberately reports missing path, time, policy, and revocation
    evidence instead of pretending the PD has done that work.
    """
    report: dict[str, Any] = {
        "x509_certificate_present": bool(smcs and smcs.get("certificate")),
        "time_validation": "not_checked",
        "path_validation": "not_checked",
        "policy_validation": "not_checked",
        "revocation_validation": "not_checked",
        "notes": [],
    }
    if not smcs or not smcs.get("certificate"):
        report["notes"].append("5FC122 content-signing certificate not supplied; ACU must retrieve or already possess it.")
        return report

    cert: x509.Certificate = smcs["certificate"]
    ski = cert_ski(cert)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    eku_oids = cert_eku_oids(cert)
    policy_oids = cert_policy_oids(cert)
    report.update(
        {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": hex(cert.serial_number),
            "subject_key_identifier": ski.hex().upper() if ski else None,
            "certificate_iin": ski[:8].hex().upper() if ski else None,
            "certificate_iin_matches_anchor": bool(ski and ski[:8] == anchor["iin"]),
            "certificate_spki_matches_anchor": spki == anchor["spki"],
            "eku_oids": eku_oids,
            "content_signing_eku_present": (
                OID_PIV_CONTENT_SIGNING_EKU in eku_oids or OID_PIVI_CONTENT_SIGNING_EKU in eku_oids
            ),
            "policy_oids": policy_oids,
        }
    )
    report["policy_validation"] = "reported"

    if validation_time is None:
        report["time_validation"] = "not_checked_no_validation_time"
    else:
        report["time_validation"] = (
            "passed"
            if cert.not_valid_before_utc <= validation_time <= cert.not_valid_after_utc
            else "failed"
        )

    if ca_bundle is None:
        report["path_validation"] = "not_checked_no_ca_bundle"
    else:
        issuers = load_pem_certs(ca_bundle)
        matched = [issuer for issuer in issuers if issuer.subject == cert.issuer]
        if not matched:
            report["path_validation"] = "failed_no_issuer_in_bundle"
        else:
            ok, reason = verify_cert_signature(cert, matched[0])
            report["path_validation"] = "passed" if ok else "failed"
            if reason:
                report["notes"].append(reason)
    report["revocation_validation"] = "not_checked_no_revocation_source"
    return report


def cvc_summary(cvc: dict[str, Any] | None) -> dict[str, Any] | None:
    """Return the CVC fields that are useful in a human-readable report."""
    if cvc is None:
        return None
    return {
        "length": cvc["length"],
        "profile": cvc["profile"],
        "iin": cvc["iin"].hex().upper(),
        "subject_identifier": cvc["subject_identifier"].hex().upper(),
        "role": cvc["role"].hex().upper(),
        "public_key_curve_oid": cvc["public_key_curve_oid"],
        "signature_algorithm_oid": cvc["signature_algorithm_oid"],
    }


def human_check_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add readable descriptions to low-level validation checks."""
    return [
        {
            "check": step["check"],
            "description": CHECK_DESCRIPTIONS.get(step["check"], step["check"].replace("_", " ")),
            "passed": step["passed"],
            "reason": step.get("reason"),
        }
        for step in steps
    ]


def human_summary(path: str | None, result_ok: bool, result_reason: str | None, anchor: dict[str, Any], secure_cvc: dict[str, Any], selected_anchor_iin: bytes | None) -> dict[str, Any]:
    """Build the first JSON object a reader should inspect."""
    cvc_iin = secure_cvc["iin"].hex().upper()
    anchor_iin = selected_anchor_iin.hex().upper() if selected_anchor_iin else None
    if result_ok:
        message = (
            f"PD validation passed using the {path} path. "
            f"The ACU should receive CVC IIN {cvc_iin} and anchor IIN {anchor_iin}."
        )
    else:
        message = f"PD validation failed using the {path or 'unknown'} path: {result_reason}."
    return {
        "status": "passed" if result_ok else "failed",
        "message": message,
        "pd_path": path,
        "trust_anchor": f"{anchor['algorithm']} IIN {anchor['iin'].hex().upper()}",
        "secure_cvc_iin": cvc_iin,
        "selected_anchor_iin": anchor_iin,
    }


def validate(args: argparse.Namespace) -> dict[str, Any]:
    anchor = parse_anchor(load_blob(args.anchor))
    secure_cvc = parse_cvc(load_blob(args.cvc), "secure_messaging_cvc")
    smcs = parse_smcs(load_blob(args.smcs)) if args.smcs else None

    # The PD first tries the fast/direct case: CVC tag 42 directly selects a
    # loaded trust anchor. If that fails, it can try the one-hop Intermediate CVC
    # flow using 5FC122.
    steps = []
    selected_anchor_iin = None
    result_ok = False
    result_reason = None
    path = None

    direct_iin_match = secure_cvc["iin"] == anchor["iin"]
    steps.append({"check": "secure_cvc_iin_matches_anchor_iin", "passed": direct_iin_match})
    if direct_iin_match:
        ok, reason = verify_signature(
            anchor["public_key"],
            secure_cvc["signature_algorithm_oid"],
            secure_cvc["signature"],
            secure_cvc["tbs"],
        )
        steps.append({"check": "secure_cvc_signature_with_anchor", "passed": ok, "reason": reason})
        selected_anchor_iin = anchor["iin"]
        result_ok = ok
        result_reason = reason
        path = "direct"
    else:
        path = "intermediate"
        if smcs is None:
            result_reason = "secure CVC IIN did not match anchor and no 5FC122 was supplied"
            steps.append({"check": "5fc122_present", "passed": False})
        elif smcs.get("intermediate_cvc") is None:
            result_reason = "secure CVC IIN did not match anchor and 5FC122 contained no Intermediate CVC"
            steps.append({"check": "intermediate_cvc_present", "passed": False})
        else:
            intermediate = smcs["intermediate_cvc"]
            checks = [
                (
                    "secure_cvc_iin_matches_intermediate_subject_identifier",
                    secure_cvc["iin"] == intermediate["subject_identifier"],
                    None,
                ),
                ("intermediate_role_is_12", intermediate["role"] == b"\x12", None),
                ("intermediate_iin_matches_anchor_iin", intermediate["iin"] == anchor["iin"], None),
            ]
            for check, passed, reason in checks:
                steps.append({"check": check, "passed": passed, "reason": reason})
            if all(passed for _, passed, _ in checks):
                ok_i, reason_i = verify_signature(
                    anchor["public_key"],
                    intermediate["signature_algorithm_oid"],
                    intermediate["signature"],
                    intermediate["tbs"],
                )
                steps.append({"check": "intermediate_cvc_signature_with_anchor", "passed": ok_i, "reason": reason_i})
                ok_c, reason_c = verify_signature(
                    intermediate["public_key"],
                    secure_cvc["signature_algorithm_oid"],
                    secure_cvc["signature"],
                    secure_cvc["tbs"],
                )
                steps.append({"check": "secure_cvc_signature_with_intermediate", "passed": ok_c, "reason": reason_c})
                selected_anchor_iin = anchor["iin"]
                result_ok = ok_i and ok_c
                result_reason = reason_i or reason_c
            else:
                result_reason = "intermediate CVC selector checks failed"

    if result_ok:
        result_reason = None

    validation_time = parse_validation_time(args.validation_time)
    acu_report = acu_validation(anchor, smcs, args.ca_bundle, validation_time)
    report = {
        "summary": human_summary(path, result_ok, result_reason, anchor, secure_cvc, selected_anchor_iin),
        "result": {
            "passed": result_ok,
            "reason": result_reason,
        },
        "reported_to_acu": {
            "vci_cvc_iin": secure_cvc["iin"].hex().upper(),
            "vci_anchor_iin": selected_anchor_iin.hex().upper() if selected_anchor_iin else None,
        },
        "pd_validation": {
            "path": path,
            "checks": human_check_steps(steps),
            "plain_english_scope": (
                "The PD validates only the immediate signer of the secure messaging CVC. "
                "It does not validate X.509 path, time, policy, or revocation."
            ),
            "validates_only_immediate_cvc_signer": True,
            "does_not_validate_x509_time_path_policy_or_revocation": True,
        },
        "acu_validation": acu_report,
        "inputs": {
            "anchor": args.anchor,
            "cvc": args.cvc,
            "smcs": args.smcs,
            "ca_bundle": str(args.ca_bundle) if args.ca_bundle else None,
            "validation_time": validation_time.isoformat() if validation_time else None,
        },
        "trust_anchor": {
            "iin": anchor["iin"].hex().upper(),
            "algorithm": anchor["algorithm"],
            "spki_length": anchor["spki_length"],
            "record_length": anchor["record_length"],
        },
        "cvc": cvc_summary(secure_cvc),
        "intermediate_cvc": cvc_summary(smcs["intermediate_cvc"]) if smcs else None,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--anchor", required=True, help="VCI trust anchor record file or hex")
    parser.add_argument("--cvc", required=True, help="Secure messaging CVC file or hex")
    parser.add_argument("--smcs", help="Optional Secure Messaging Certificate Signer object, tag 5FC122/53, file or hex")
    parser.add_argument("--ca-bundle", type=Path, help="Optional PEM/DER issuer certificate bundle for ACU path check")
    parser.add_argument("--validation-time", help="Optional ISO-8601 time used for ACU certificate validity check")
    parser.add_argument("--output", type=Path, help="Optional path to write the same readable JSON report")
    args = parser.parse_args()

    try:
        report = validate(args)
        json_report = json.dumps(report, indent=2) + "\n"
        if args.output:
            args.output.write_text(json_report, encoding="utf-8")
        print(json_report, end="")
        return 0 if report["result"]["passed"] else 2
    except Exception as exc:  # noqa: BLE001 - command-line diagnostic
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
