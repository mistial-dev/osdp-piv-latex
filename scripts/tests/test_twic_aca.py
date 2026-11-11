import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from piv_auto_apdu import (
    derive_twic_aca_challenge, encode_tlv, general_authenticate_apdu,
    parse_dynamic_auth_response, parse_general_authenticate_apdu,
    simulate_card_response,
)
from twic_aca_examples import (
    AcaAttempt, TWIC_ACA_CAPABILITIES, TWIC_FASCN_OID, application_for_aid,
    certificate_identity, certificate_profile, validate_configuration,
)

FASCN = bytes(range(1, 26))
KDK = bytes(range(32))
ENTROPY = bytes(range(32))
TWIC_ENTRY = bytes.fromhex("010D020209A000000367200000019E")
PIV_ENTRY = bytes.fromhex("01040102009E")


def configuration(entries=TWIC_ENTRY, count=1):
    return (bytes([1, count, 2]) + (7).to_bytes(4, "little")
            + (42).to_bytes(4, "little") + ENTROPY + entries)


def certificate(key, fascn=FASCN, *, oid=TWIC_FASCN_OID):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "TWIC ACA test")])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.OtherName(oid, encode_tlv(4, fascn))]), critical=False)
            .sign(key, hashes.SHA256()))


class TwicAcaTests(unittest.TestCase):
    def test_interface_masks_match_fc13_physical_interface_bits(self):
        for mask in range(256):
            for field in ("global", "entry"):
                with self.subTest(mask=mask, field=field):
                    data = bytearray(configuration())
                    data[2] = mask if field == "global" else 0
                    data[46] = 0 if field == "global" else mask
                    if mask & ~0x13:
                        with self.assertRaises(ValueError):
                            validate_configuration(bytes(data), TWIC_ACA_CAPABILITIES)
                    else:
                        validate_configuration(bytes(data), TWIC_ACA_CAPABILITIES)

    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.ec_key = ec.generate_private_key(ec.SECP384R1())
        cls.rsa_cert = certificate(cls.rsa_key)
        cls.ec_cert = certificate(cls.ec_key)

    def attempt(self, cert=None, **changes):
        values = dict(presentation=11, certificate=cert or self.rsa_cert, kdk=KDK,
                      series=7, sequence=42, entropy=ENTROPY)
        values.update(changes)
        return AcaAttempt(**values)

    def test_known_answer_from_independent_openssl_kmac256(self):
        template, challenge, _ = self.attempt().inputs()
        self.assertEqual(len(template), 0x61)
        self.assertEqual(template[47:63], bytes(16))
        # OpenSSL KMAC-256, size 127, custom OSDP-TWIC-AUTO-CHALLENGE-v1.
        self.assertEqual(challenge.hex().upper(),
            "4F1B89BCDC16826AEB2718C3E1A23C76C3230B85E43326D8049B40EF8D1B3E37"
            "49360C237AED2C356EC36D854682968CF1B696CCF6114F0166486AC147D0FE8C5"
            "6F0F2C3184CDB44989BD0922D6FC68B3E3C8C2585C767EB42389B4777268314"
            "1FBC9EAECCD871B0A7EA6A9D3B5CA068FC7C42ACDB88180AF2C92573699114")
        self.assertEqual(hashlib.sha256(challenge).hexdigest().upper(),
                         "58CC42015E3435736D2CE461C7CCF169ABC179F0741125CD60097424521CAA0D")

    def test_rsa_and_ecc_proofs_verify_against_full_challenge_message(self):
        for key, cert in [(self.rsa_key, self.rsa_cert), (self.ec_key, self.ec_cert)]:
            with self.subTest(key=type(key).__name__):
                attempt = self.attempt(cert)
                profile = certificate_profile(cert)
                _, challenge, input_value = attempt.inputs()
                self.assertEqual(len(challenge), 127)
                apdu = general_authenticate_apdu(profile, input_value)
                parsed = parse_general_authenticate_apdu(apdu)
                self.assertEqual(parsed["key_ref"], 0x9E)
                self.assertEqual(parsed["algorithm_id"], profile.algorithm_id)
                self.assertEqual(len(parsed["input"]), 256 if profile.algorithm_id == 7 else 48)
                response = simulate_card_response(profile, key, input_value)
                # Independent verification hashes the complete challenge message itself.
                signature = parse_dynamic_auth_response(response)["82"]
                if isinstance(key, rsa.RSAPrivateKey):
                    key.public_key().verify(signature, challenge, padding.PKCS1v15(), hashes.SHA256())
                else:
                    key.public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA384()))
                attempt.verify_proof(11, certificate(key), response)
                self.assertEqual(attempt.inputs(), self.attempt(cert).inputs())

    def test_counter_identity_and_entropy_changes_invalidate_proof(self):
        attempt = self.attempt()
        profile = certificate_profile(self.rsa_cert)
        response = simulate_card_response(profile, self.rsa_key, attempt.inputs()[2])
        changed_cert = certificate(self.rsa_key, FASCN[::-1])
        for changes in [dict(series=8), dict(sequence=43), dict(entropy=bytes(32)),
                        dict(certificate=changed_cert)]:
            with self.subTest(changes=list(changes)):
                other = self.attempt(**changes)
                with self.assertRaises(InvalidSignature):
                    other.verify_proof(11, other.certificate, response)
        with self.assertRaises(InvalidSignature):
            attempt.verify_proof(11, changed_cert, response)

    def test_retrieved_certificate_must_hold_the_proving_key(self):
        response = simulate_card_response(certificate_profile(self.rsa_cert), self.rsa_key,
                                         self.attempt().inputs()[2])
        different_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with self.assertRaises(InvalidSignature):
            self.attempt().verify_proof(11, certificate(different_key), response)

    def test_presentation_loss_or_replacement_permanently_ends_attempt(self):
        for event in [None, 12]:
            with self.subTest(event=event):
                attempt = self.attempt()
                response = simulate_card_response(certificate_profile(self.rsa_cert), self.rsa_key,
                                                 attempt.inputs()[2])
                with self.assertRaises(ValueError):
                    attempt.verify_proof(event, self.rsa_cert, response)
                with self.assertRaises(ValueError):
                    attempt.verify_proof(11, self.rsa_cert, response)
                with self.assertRaises(ValueError):
                    attempt.inputs()

    def test_application_transition_preserves_same_presentation(self):
        attempt = self.attempt()
        self.assertEqual(application_for_aid(bytes.fromhex("A000000367200000010101")),
                         bytes.fromhex("A000000308000010000100"))
        attempt.check_continuity(11)
        self.assertEqual(application_for_aid(bytes.fromhex("A000000367200000010104")),
                         bytes.fromhex("A000000367200000010104"))
        attempt.check_continuity(11)
        self.assertEqual(len(attempt.inputs()[1]), 127)

    def test_v8_v10_and_unknown_minor_remain_in_twic_application(self):
        for minor in [3, 4, 5]:
            aid = bytes.fromhex("A0000003672000000101") + bytes([minor])
            self.assertEqual(application_for_aid(aid), aid)
        for suffix in [b"", b"\x01\x00", b"\x01\xff", b"\x02\x04"]:
            with self.assertRaises(ValueError):
                application_for_aid(bytes.fromhex("A00000036720000001") + suffix)

    def test_capability_gates_configuration(self):
        validate_configuration(configuration(), TWIC_ACA_CAPABILITIES)
        for missing in [4, 8, 16]:
            with self.assertRaises(ValueError):
                validate_configuration(configuration(), TWIC_ACA_CAPABILITIES & ~missing)

    def test_twiconly_configuration_and_optional_resume(self):
        validate_configuration(configuration(TWIC_ENTRY * 2, 2), TWIC_ACA_CAPABILITIES)
        validate_configuration(configuration() + bytes.fromhex("02080700000029000000"),
                               TWIC_ACA_CAPABILITIES)
        for data in [configuration(TWIC_ENTRY + PIV_ENTRY, 2),
                     configuration(TWIC_ENTRY[:-1] + b"\x9a"),
                     configuration(count=2), configuration()[:-1],
                     configuration() + b"\x00", configuration() + TWIC_ENTRY]:
            with self.subTest(data=data.hex()):
                with self.assertRaises(ValueError):
                    validate_configuration(data, TWIC_ACA_CAPABILITIES)

    def test_certificate_identity_is_required_without_a_chuid(self):
        self.assertEqual(certificate_identity(self.rsa_cert), FASCN)
        for fascn in [b"", bytes(25), FASCN[:-1]]:
            with self.assertRaises(ValueError):
                certificate_identity(certificate(self.rsa_key, fascn))
        with self.assertRaises(ValueError):
            certificate_identity(certificate(self.rsa_key, oid=x509.ObjectIdentifier("1.2.3")))

    def test_unsupported_subject_key_fails_profile_discovery(self):
        for key in [ec.generate_private_key(ec.SECP256R1()),
                    rsa.generate_private_key(public_exponent=65537, key_size=3072)]:
            with self.assertRaises(ValueError):
                certificate_profile(certificate(key))

    def test_challenge_rejects_invalid_profile_inputs(self):
        template = self.attempt().inputs()[0]
        for offset, value in [(47, 1), (63, 0x9A), (64, 0x11)]:
            data = bytearray(template)
            data[offset] = value
            with self.assertRaises(ValueError):
                derive_twic_aca_challenge(KDK, bytes(data))
        for kdk, data in [(KDK[:-1], template), (KDK, template[:-1])]:
            with self.assertRaises(ValueError):
                derive_twic_aca_challenge(kdk, data)


if __name__ == "__main__":
    unittest.main()
