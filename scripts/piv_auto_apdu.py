#!/usr/bin/env python3
"""PIV Auto profile, TLV, and GENERAL AUTHENTICATE helpers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import pkcs12

try:
    from Crypto.Hash import KMAC256
except ModuleNotFoundError:
    from Cryptodome.Hash import KMAC256


PIV_AID = bytes.fromhex("A000000308000010000100")
PIV_AUTO_KDK_CUSTOMIZATION = b"OSDP-PIV-AUTO-KDK-v1"
PIV_AUTO_CHALLENGE_CUSTOMIZATION = b"OSDP-PIV-AUTO-CHALLENGE-v1"


class Operation(str, Enum):
    AUTHENTICATE = "authenticate"
    SIGN = "sign"
    KEY_AGREEMENT = "key_agreement"


@dataclass(frozen=True)
class PivProfile:
    profile_id: str
    label: str
    algorithm_id: int
    key_ref: int
    operation: Operation
    key_type: str
    digest_name: str
    challenge_len: int
    response_len: int | None
    current: bool
    piv_auto: bool
    source_note: str


PROFILES: dict[str, PivProfile] = {
    "9a-rsa1024": PivProfile(
        "9a-rsa1024", "PIV Authentication RSA-1024", 0x06, 0x9A, Operation.AUTHENTICATE,
        "rsa1024", "sha256", 128, 128, False, False, "Informative legacy/non-current test-only coverage",
    ),
    "9e-rsa1024": PivProfile(
        "9e-rsa1024", "Card Authentication RSA-1024", 0x06, 0x9E, Operation.AUTHENTICATE,
        "rsa1024", "sha256", 128, 128, False, False, "Informative legacy/non-current test-only coverage",
    ),
    "9a-rsa2048": PivProfile(
        "9a-rsa2048", "PIV Authentication RSA-2048", 0x07, 0x9A, Operation.AUTHENTICATE,
        "rsa2048", "sha256", 256, 256, True, True, "NIST SD 33 / IR 8347 and generated-card coverage",
    ),
    "9e-rsa2048": PivProfile(
        "9e-rsa2048", "Card Authentication RSA-2048", 0x07, 0x9E, Operation.AUTHENTICATE,
        "rsa2048", "sha256", 256, 256, True, True, "NIST SD 33 / IR 8347 and generated-card coverage",
    ),
    "9a-rsa3072": PivProfile(
        "9a-rsa3072", "PIV Authentication RSA-3072", 0x05, 0x9A, Operation.AUTHENTICATE,
        "rsa3072", "sha384", 384, 384, True, True, "Generated-card coverage",
    ),
    "9e-rsa3072": PivProfile(
        "9e-rsa3072", "Card Authentication RSA-3072", 0x05, 0x9E, Operation.AUTHENTICATE,
        "rsa3072", "sha384", 384, 384, True, True, "Generated-card coverage",
    ),
    "9a-ecp256": PivProfile(
        "9a-ecp256", "PIV Authentication ECC P-256", 0x11, 0x9A, Operation.AUTHENTICATE,
        "ecp256", "sha256", 32, None, True, True, "NIST SD 33 / IR 8347 and generated-card coverage",
    ),
    "9e-ecp256": PivProfile(
        "9e-ecp256", "Card Authentication ECC P-256", 0x11, 0x9E, Operation.AUTHENTICATE,
        "ecp256", "sha256", 32, None, True, True, "NIST SD 33 / IR 8347 and generated-card coverage",
    ),
    "9a-ecp384": PivProfile(
        "9a-ecp384", "PIV Authentication ECC P-384", 0x14, 0x9A, Operation.AUTHENTICATE,
        "ecp384", "sha384", 48, None, True, True, "Generated-card coverage",
    ),
    "9e-ecp384": PivProfile(
        "9e-ecp384", "Card Authentication ECC P-384", 0x14, 0x9E, Operation.AUTHENTICATE,
        "ecp384", "sha384", 48, None, True, True, "Generated-card coverage",
    ),
    "9c-ecp384": PivProfile(
        "9c-ecp384", "Digital Signature ECC P-384", 0x14, 0x9C, Operation.SIGN,
        "ecp384", "sha384", 48, None, True, False, "NIST SD 33 APDU validation example, not PIV Auto",
    ),
    "9d-ecp384": PivProfile(
        "9d-ecp384", "Key Management ECC P-384", 0x14, 0x9D, Operation.KEY_AGREEMENT,
        "ecp384", "sha384", 97, 48, True, False, "NIST SD 33 APDU validation example, not PIV Auto",
    ),
}

PIV_AUTO_PROFILE_IDS = [profile_id for profile_id, profile in PROFILES.items() if profile.piv_auto]
INFORMATIVE_LEGACY_PROFILE_IDS = [
    profile_id for profile_id, profile in PROFILES.items() if not profile.current and not profile.piv_auto
]


def derive_piv_auto_kdk(sc2_session_keys: bytes) -> bytes:
    """Derive the 32-byte PIV Auto KDK from concatenated SC2 session keys."""
    if len(sc2_session_keys) != 48:
        raise ValueError("SC2 session-key material must be S-ENC || S-MAC1 || S-MAC2 (48 bytes)")
    kmac = KMAC256.new(
        key=sc2_session_keys,
        data=b"",
        mac_len=32,
        custom=PIV_AUTO_KDK_CUSTOMIZATION,
    )
    return kmac.digest()


def derive_piv_auto_challenge(piv_auto_kdk: bytes, template: bytes, length: int) -> bytes:
    """Derive a PIV Auto challenge digest from the PIV Auto KDK."""
    if len(piv_auto_kdk) != 32:
        raise ValueError("PIV Auto KDK must be 32 bytes")
    if length not in {32, 48}:
        raise ValueError("PIV Auto challenge digest length must be 32 or 48 bytes")
    kmac = KMAC256.new(
        key=piv_auto_kdk,
        data=template,
        mac_len=length,
        custom=PIV_AUTO_CHALLENGE_CUSTOMIZATION,
    )
    return kmac.digest()


def encode_len(length: int) -> bytes:
    if length < 0:
        raise ValueError("negative length")
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode_tlv(tag: int | bytes, value: bytes) -> bytes:
    tag_bytes = bytes([tag]) if isinstance(tag, int) else tag
    return tag_bytes + encode_len(len(value)) + value


def read_len(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    count = first & 0x7F
    if count == 0:
        raise ValueError("indefinite length is not supported")
    if offset + count > len(data):
        raise ValueError("truncated length")
    return int.from_bytes(data[offset : offset + count], "big"), offset + count


def read_tlv(data: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, int]:
    start = offset
    if offset >= len(data):
        raise ValueError("missing tag")
    tag = [data[offset]]
    offset += 1
    if tag[0] & 0x1F == 0x1F:
        while True:
            if offset >= len(data):
                raise ValueError("truncated high-tag-number tag")
            tag.append(data[offset])
            more = data[offset] & 0x80
            offset += 1
            if not more:
                break
    length, value_offset = read_len(data, offset)
    end = value_offset + length
    if end > len(data):
        raise ValueError("truncated value")
    return bytes(tag), data[value_offset:end], data[start:end], end


def children(data: bytes) -> list[tuple[bytes, bytes, bytes]]:
    out = []
    offset = 0
    while offset < len(data):
        tag, value, tlv, offset = read_tlv(data, offset)
        out.append((tag, value, tlv))
    return out


def select_piv_apdu() -> bytes:
    return b"\x00\xA4\x04\x00" + bytes([len(PIV_AID)]) + PIV_AID


def get_data_apdu(object_tag: bytes) -> bytes:
    data = encode_tlv(0x5C, object_tag)
    return b"\x00\xCB\x3F\xFF" + bytes([len(data)]) + data


def verify_pin_apdu(pin: str, reference: int = 0x80) -> bytes:
    pin_bytes = pin.encode("ascii")
    if len(pin_bytes) > 8:
        raise ValueError("PIV PIN must be at most 8 bytes")
    return b"\x00\x20\x00" + bytes([reference, 0x08]) + pin_bytes.ljust(8, b"\xFF")


def dynamic_auth_template(input_value: bytes, *, input_tag: int = 0x81) -> bytes:
    return encode_tlv(0x7C, encode_tlv(0x82, b"") + encode_tlv(input_tag, input_value))


def general_authenticate_apdu(profile: PivProfile, input_value: bytes, *, cla: int = 0x00, le: int | None = 0x00) -> bytes:
    input_tag = 0x85 if profile.operation is Operation.KEY_AGREEMENT else 0x81
    data = dynamic_auth_template(input_value, input_tag=input_tag)
    if len(data) <= 255:
        apdu = bytes([cla, 0x87, profile.algorithm_id, profile.key_ref, len(data)]) + data
    else:
        apdu = bytes([cla, 0x87, profile.algorithm_id, profile.key_ref, 0x00]) + len(data).to_bytes(2, "big") + data
    if le is not None:
        apdu += bytes([le])
    return apdu


def parse_general_authenticate_apdu(apdu: bytes) -> dict[str, Any]:
    if len(apdu) < 5 or apdu[1] != 0x87:
        raise ValueError("not a GENERAL AUTHENTICATE APDU")
    cla, _ins, alg, key_ref, lc1 = apdu[:5]
    offset = 5
    if lc1 == 0:
        if len(apdu) < 7:
            raise ValueError("truncated extended APDU")
        lc = int.from_bytes(apdu[5:7], "big")
        offset = 7
    else:
        lc = lc1
    data = apdu[offset : offset + lc]
    if len(data) != lc:
        raise ValueError("truncated APDU data")
    le = apdu[offset + lc :] or None
    tag, dat_value, _tlv, end = read_tlv(data)
    if tag != b"\x7C" or end != len(data):
        raise ValueError("GENERAL AUTHENTICATE data must be one 7C template")
    fields = {tag: value for tag, value, _ in children(dat_value)}
    return {
        "cla": cla,
        "algorithm_id": alg,
        "key_ref": key_ref,
        "data": data,
        "response_requested": b"\x82" in fields and fields[b"\x82"] == b"",
        "input": fields.get(b"\x81", fields.get(b"\x85", b"")),
        "input_tag": 0x81 if b"\x81" in fields else 0x85 if b"\x85" in fields else None,
        "le": le,
    }


def parse_dynamic_auth_response(response: bytes) -> dict[str, bytes]:
    body = response[:-2] if len(response) >= 2 and response[-2:] == b"\x90\x00" else response
    tag, dat_value, _tlv, end = read_tlv(body)
    if tag != b"\x7C" or end != len(body):
        raise ValueError("response must be one 7C template")
    return {tag.hex().upper(): value for tag, value, _ in children(dat_value)}


def chunk_command_apdu(apdu: bytes, *, max_data: int = 255) -> list[bytes]:
    parsed = parse_general_authenticate_apdu(apdu)
    data = parsed["data"]
    if len(data) <= max_data:
        return [apdu]
    chunks = []
    for offset in range(0, len(data), max_data):
        cla = parsed["cla"] | 0x10 if offset + max_data < len(data) else parsed["cla"] & ~0x10
        piece = data[offset : offset + max_data]
        chunks.append(bytes([cla, 0x87, parsed["algorithm_id"], parsed["key_ref"], len(piece)]) + piece)
    chunks[-1] += b"\x00"
    return chunks


def digest_algorithm(name: str) -> hashes.HashAlgorithm:
    if name == "sha256":
        return hashes.SHA256()
    if name == "sha384":
        return hashes.SHA384()
    raise ValueError(f"unsupported digest: {name}")


def digest_info_prefix(name: str) -> bytes:
    if name == "sha256":
        return bytes.fromhex("3031300d060960864801650304020105000420")
    if name == "sha384":
        return bytes.fromhex("3041300d060960864801650304020205000430")
    raise ValueError(f"unsupported digest: {name}")


def emsa_pkcs1_v1_5_digest_block(digest: bytes, modulus_len: int, digest_name: str) -> bytes:
    t = digest_info_prefix(digest_name) + digest
    if len(t) + 11 > modulus_len:
        raise ValueError("encoded digest is too long for RSA modulus")
    return b"\x00\x01" + (b"\xFF" * (modulus_len - len(t) - 3)) + b"\x00" + t


def profile_input(profile: PivProfile, digest: bytes) -> bytes:
    if profile.key_type.startswith("rsa"):
        return emsa_pkcs1_v1_5_digest_block(digest, profile.challenge_len, profile.digest_name)
    if len(digest) != profile.challenge_len and profile.operation is not Operation.KEY_AGREEMENT:
        raise ValueError(f"{profile.profile_id} expects {profile.challenge_len} bytes of digest/input")
    return digest


def rsa_private_operation(private_key: rsa.RSAPrivateKey, value: bytes) -> bytes:
    numbers: RSAPrivateNumbers = private_key.private_numbers()
    modulus_len = (numbers.public_numbers.n.bit_length() + 7) // 8
    if len(value) != modulus_len:
        raise ValueError("RSA private operation input length must equal modulus length")
    output = pow(int.from_bytes(value, "big"), numbers.d, numbers.public_numbers.n)
    return output.to_bytes(modulus_len, "big")


def simulate_card_response(profile: PivProfile, private_key: object, input_value: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        response = rsa_private_operation(private_key, input_value)
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = ec.ECDSA(utils.Prehashed(digest_algorithm(profile.digest_name)), deterministic_signing=True)
        response = private_key.sign(input_value, algorithm)
    else:
        raise TypeError(f"unsupported private key: {private_key.__class__.__name__}")
    return encode_tlv(0x7C, encode_tlv(0x82, response)) + b"\x90\x00"


def verify_card_response(profile: PivProfile, public_key: object, input_value: bytes, response: bytes) -> None:
    fields = parse_dynamic_auth_response(response)
    signature = fields.get("82")
    if signature is None:
        raise ValueError("missing 82 response tag")
    if isinstance(public_key, rsa.RSAPublicKey):
        modulus_len = (public_key.public_numbers().n.bit_length() + 7) // 8
        recovered = pow(int.from_bytes(signature, "big"), public_key.public_numbers().e, public_key.public_numbers().n)
        if recovered.to_bytes(modulus_len, "big") != input_value:
            raise InvalidSignature("RSA private operation response does not recover input")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, input_value, ec.ECDSA(utils.Prehashed(digest_algorithm(profile.digest_name))))
        return
    raise TypeError(f"unsupported public key: {public_key.__class__.__name__}")


def load_pkcs12_key(path: Path, password: bytes | None = None) -> tuple[object, object]:
    private_key, certificate, _additional = pkcs12.load_key_and_certificates(path.read_bytes(), password)
    if private_key is None or certificate is None:
        raise ValueError(f"{path} does not contain a private key and certificate")
    return private_key, certificate


def public_key_der(public_key: object) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def profile_by_alg_ref(algorithm_id: int, key_ref: int) -> PivProfile | None:
    for profile in PROFILES.values():
        if profile.algorithm_id == algorithm_id and profile.key_ref == key_ref:
            return profile
    return None
