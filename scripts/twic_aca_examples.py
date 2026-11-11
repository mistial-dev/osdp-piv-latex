"""Executable TWIC ACA profile examples for the proposal's configuration and proof rules."""
from dataclasses import dataclass
import hashlib
import hmac

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from piv_auto_apdu import (
    PROFILES, derive_twic_aca_challenge, profile_input, read_tlv,
    verify_card_response,
)

TWIC_FASCN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.29138.6.6")
TWIC_ACA_CAPABILITIES = 0x04 | 0x08 | 0x10
PIVMODE_INTERFACE_MASK = 0x01 | 0x02 | 0x10


def validate_configuration(data: bytes, capabilities: int) -> None:
    """Validate a reassembled TWIC-only Auto configuration before installation."""
    if capabilities & TWIC_ACA_CAPABILITIES != TWIC_ACA_CAPABILITIES:
        raise ValueError("TWIC ACA capability is required")
    if len(data) < 49 or not data[0] & 0x01 or data[0] & ~0x07:
        raise ValueError("invalid Auto configuration header")
    count, global_mask = data[1:3]
    if not 1 <= count <= 32 or global_mask & ~PIVMODE_INTERFACE_MASK:
        raise ValueError("invalid count or interface mask")
    offset = 43
    for _ in range(count):
        if offset + 2 > len(data) or data[offset + 1] > 20:
            raise ValueError("truncated or invalid Configuration Entry")
        tag, entry, _, offset = read_tlv(data, offset)
        if tag != b"\x01" or len(entry) < 4:
            raise ValueError("invalid Configuration Entry")
        model, mask, aid_length = entry[:3]
        if model != 2 or entry[-1] != 0x9E:
            raise ValueError("TWIC ACA configuration requires TWIC entries with key 9E")
        if aid_length > 16 or len(entry) != 4 + aid_length:
            raise ValueError("invalid AID length")
        if mask & ~PIVMODE_INTERFACE_MASK or (global_mask and mask & ~global_mask):
            raise ValueError("invalid entry interface mask")
    if offset < len(data):
        if offset + 2 > len(data) or data[offset + 1] != 8:
            raise ValueError("invalid Resume TLV")
        tag, resume, _, offset = read_tlv(data, offset)
        if tag != b"\x02" or len(resume) != 8:
            raise ValueError("invalid Resume TLV")
    if offset != len(data):
        raise ValueError("trailing configuration data")


def certificate_identity(certificate: x509.Certificate) -> bytes:
    """Extract the certified twicFASC-N OtherName's 25-byte OCTET STRING."""
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("certified twicFASC-N is required") from exc
    entries = [name.value for name in san.get_values_for_type(x509.OtherName)
               if name.type_id == TWIC_FASCN_OID]
    if len(entries) != 1:
        raise ValueError("one certified twicFASC-N is required")
    try:
        tag, fascn, _, end = read_tlv(entries[0])
    except (IndexError, ValueError) as exc:
        raise ValueError("invalid certified FASC-N encoding") from exc
    if tag != b"\x04" or end != len(entries[0]) or len(fascn) != 25 or not any(fascn):
        raise ValueError("invalid certified FASC-N")
    return fascn


def certificate_profile(certificate: x509.Certificate):
    key = certificate.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size == 2048:
        return PROFILES["9e-rsa2048"]
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1):
        return PROFILES["9e-ecp384"]
    raise ValueError("unsupported TWIC ACA subject key")


def application_for_aid(aid: bytes) -> bytes:
    prefix = bytes.fromhex("A00000036720000001")
    if len(aid) != 11 or not aid.startswith(prefix) or aid[9] != 1 or aid[10] in (0, 255):
        raise ValueError("full supported TWIC major-version evidence is required")
    if aid[10] == 1:
        return bytes.fromhex("A000000308000010000100")
    return aid


@dataclass
class AcaAttempt:
    presentation: int
    certificate: x509.Certificate
    kdk: bytes
    series: int
    sequence: int
    entropy: bytes
    active: bool = True

    def check_continuity(self, presentation: int | None) -> None:
        if not self.active or presentation != self.presentation:
            self.active = False
            raise ValueError("credential presentation ended")

    def inputs(self) -> tuple[bytes, bytes, bytes]:
        if not self.active:
            raise ValueError("credential presentation ended")
        if len(self.entropy) != 32:
            raise ValueError("Supplemental Entropy must be 32 bytes")
        profile = certificate_profile(self.certificate)
        template = (b"OSDP-PIV-AUTO\x01" + self.series.to_bytes(4, "little")
                    + self.sequence.to_bytes(4, "little") + certificate_identity(self.certificate)
                    + bytes(16) + bytes([0x9E, profile.algorithm_id]) + self.entropy)
        challenge = derive_twic_aca_challenge(self.kdk, template)
        digest = hashlib.new(profile.digest_name, challenge).digest()
        return template, challenge, profile_input(profile, digest)

    def verify_proof(self, presentation: int | None, certificate: x509.Certificate,
                     response: bytes) -> None:
        """Check continuity and reconstruct the proof using a freshly retrieved certificate."""
        self.check_continuity(presentation)
        original_profile = certificate_profile(self.certificate)
        profile = certificate_profile(certificate)
        if (profile.algorithm_id != original_profile.algorithm_id
                or not hmac.compare_digest(certificate_identity(certificate),
                                           certificate_identity(self.certificate))):
            raise InvalidSignature("certificate identity or algorithm differs from status")
        _, _, input_value = self.inputs()
        verify_card_response(profile, certificate.public_key(), input_value, response)
