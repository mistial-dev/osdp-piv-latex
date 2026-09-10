import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509

from piv_auto_apdu import (
    PROFILES,
    PIV_AUTO_PROFILE_IDS,
    derive_piv_auto_challenge,
    derive_piv_auto_kdk,
    chunk_command_apdu,
    general_authenticate_apdu,
    parse_dynamic_auth_response,
    parse_general_authenticate_apdu,
    profile_input,
    select_piv_apdu,
    simulate_card_response,
    verify_card_response,
    verify_pin_apdu,
)
from capture_piv_auto_apdus import select_reader
from render_piv_auto_appendix_tables import (
    DEFAULT_OUTPUT,
    render,
    segmented_dynamic_auth_response,
    segmented_general_authenticate_apdu,
)
from simulate_piv_auto import (
    build_pivmode_payload,
    build_vciloada_payload,
    chunk_multipart_payload,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class PivAutoApduTests(unittest.TestCase):
    def test_generic_multipart_fields_reassemble_complete_payload(self):
        payload = bytes(range(23))
        fragments = chunk_multipart_payload(
            payload, 7, message="osdp_PIVMODE", message_code="0xAE"
        )
        self.assertEqual({fragment["MpSizeTotal"] for fragment in fragments}, {len(payload)})
        self.assertEqual([fragment["MpOffset"] for fragment in fragments], [0, 7, 14, 21])
        self.assertEqual([fragment["MpFragmentSize"] for fragment in fragments], [7, 7, 7, 2])
        self.assertEqual(
            b"".join(bytes.fromhex(fragment["fragment_data_hex"]) for fragment in fragments),
            payload,
        )

    def test_pivmode_payload_encodes_complete_configuration(self):
        entropy = bytes(range(32))
        payload = build_pivmode_payload(7, 42, entropy)
        self.assertEqual(len(payload), 48)
        self.assertEqual(payload[:3], b"\x01\x01\x03")
        self.assertEqual(payload[3:7], (7).to_bytes(4, "little"))
        self.assertEqual(payload[7:11], (42).to_bytes(4, "little"))
        self.assertEqual(payload[-5:], b"\x01\x03\x01\x03\x00")

    def test_vciloada_payload_includes_metadata_in_total(self):
        anchor = b"\x7f\x50\x01\x00"
        payload = build_vciloada_payload(anchor, b"12345678", anchor_id=1)
        self.assertEqual(len(payload), 12 + len(anchor))
        self.assertEqual(payload[:10], b"\x00\x01" + b"12345678")
        self.assertEqual(payload[10:12], len(anchor).to_bytes(2, "little"))
        self.assertEqual(payload[12:], anchor)

    def test_live_capture_reader_selection_fails_on_missing_requested_reader(self):
        with self.assertRaises(SystemExit) as caught:
            select_reader(["Reader A", "Reader B"], "Missing Reader")
        self.assertIn("Requested PC/SC reader not found", str(caught.exception))
        self.assertIn("Reader A", str(caught.exception))

    def test_live_capture_reader_selection_defaults_only_without_request(self):
        self.assertEqual(select_reader(["Reader A", "Reader B"], None), "Reader A")
        self.assertEqual(select_reader(["Reader A", "Reader B"], "Reader B"), "Reader B")

    def test_select_piv_apdu(self):
        self.assertEqual(select_piv_apdu().hex().upper(), "00A404000BA000000308000010000100")

    def test_verify_pin_apdu(self):
        self.assertEqual(verify_pin_apdu("123456").hex().upper(), "0020008008313233343536FFFF")

    def test_profile_apdu_shapes(self):
        digest = hashlib.sha256(b"piv-auto").digest()
        for profile_id in [
            "9e-rsa1024",
            "9e-rsa2048",
            "9e-rsa3072",
            "9e-ecp256",
            "9e-ecp384",
            "9a-ecp256",
        ]:
            profile = PROFILES[profile_id]
            input_value = profile_input(profile, digest if profile.digest_name == "sha256" else hashlib.sha384(b"piv-auto").digest())
            apdu = general_authenticate_apdu(profile, input_value)
            parsed = parse_general_authenticate_apdu(apdu)
            self.assertEqual(parsed["algorithm_id"], profile.algorithm_id)
            self.assertEqual(parsed["key_ref"], profile.key_ref)
            self.assertTrue(parsed["response_requested"])
            self.assertEqual(parsed["input"], input_value)
            self.assertEqual(parsed["input_tag"], 0x81)

    def test_rsa1024_is_informative_not_supported_piv_auto(self):
        self.assertNotIn("9a-rsa1024", PIV_AUTO_PROFILE_IDS)
        self.assertNotIn("9e-rsa1024", PIV_AUTO_PROFILE_IDS)
        self.assertFalse(PROFILES["9a-rsa1024"].piv_auto)
        self.assertFalse(PROFILES["9e-rsa1024"].piv_auto)

    def test_piv_auto_kdk_and_challenge_are_stable(self):
        sc2_keys = bytes.fromhex(
            "00112233445566778899AABBCCDDEEFF"
            "102132435465768798A9BACBDCEDFE0F"
            "FFEEDDCCBBAA99887766554433221100"
        )
        template = b"OSDP-PIV-AUTO\x01" + b"\x00" * 67
        kdk = derive_piv_auto_kdk(sc2_keys)
        challenge = derive_piv_auto_challenge(kdk, template, 32)
        self.assertEqual(kdk.hex().upper(), "10FFA4469E902660BA4BEF8C917696848570B20531723D67ECD934A23BA4C89D")
        self.assertEqual(challenge.hex().upper(), "E0CBA3FE6FFC4CEA31C055A9FDE80FCFC6A016AB165CE6D676F5659632BCC14E")

    def test_ecc_key_agreement_uses_exponentiation_tag_only_for_9d(self):
        input_value = b"\x04" + (b"\xAA" * 96)
        apdu = general_authenticate_apdu(PROFILES["9d-ecp384"], input_value)
        parsed = parse_general_authenticate_apdu(apdu)
        self.assertEqual(parsed["algorithm_id"], 0x14)
        self.assertEqual(parsed["key_ref"], 0x9D)
        self.assertEqual(parsed["input"], input_value)
        self.assertEqual(parsed["input_tag"], 0x85)

    def test_rsa_card_private_operation_response(self):
        profile = PROFILES["9e-rsa2048"]
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        input_value = profile_input(profile, hashlib.sha256(b"challenge").digest())
        response = simulate_card_response(profile, private_key, input_value)
        fields = parse_dynamic_auth_response(response)
        self.assertEqual(len(fields["82"]), 256)
        verify_card_response(profile, private_key.public_key(), input_value, response)

    def test_ec_prehashed_response(self):
        profile = PROFILES["9e-ecp384"]
        private_key = ec.generate_private_key(ec.SECP384R1())
        input_value = hashlib.sha384(b"challenge").digest()
        response = simulate_card_response(profile, private_key, input_value)
        self.assertIn("82", parse_dynamic_auth_response(response))
        verify_card_response(profile, private_key.public_key(), input_value, response)

    def test_command_chunking_keeps_final_le(self):
        profile = PROFILES["9e-rsa3072"]
        input_value = profile_input(profile, hashlib.sha384(b"challenge").digest())
        apdu = general_authenticate_apdu(profile, input_value)
        chunks = chunk_command_apdu(apdu, max_data=240)
        self.assertGreater(len(chunks), 1)
        self.assertEqual(chunks[-1][-1], 0)
        self.assertTrue(chunks[0][0] & 0x10)
        self.assertFalse(chunks[-1][0] & 0x10)

    def test_committed_yubikey_material_matches_manifest(self):
        material_dir = REPO_ROOT / "test-vectors" / "piv-auto-yubikey-material"
        manifest = json.loads((material_dir / "manifest.json").read_text(encoding="utf-8"))
        seen_key_types = set()
        for item in manifest["profiles"]:
            profile = PROFILES[item["profile"]]
            key = serialization.load_pem_private_key((material_dir / item["private_key"]).read_bytes(), None)
            cert = x509.load_pem_x509_certificate((material_dir / item["certificate"]).read_bytes())
            self.assertEqual(
                key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
            )
            if isinstance(key, rsa.RSAPrivateKey):
                self.assertIn(key.key_size, {1024, 3072})
            if isinstance(key, ec.EllipticCurvePrivateKey):
                self.assertEqual(key.curve.name, "secp384r1")
            seen_key_types.add(profile.key_type)
        self.assertEqual(seen_key_types, {"rsa1024", "rsa3072", "ecp384"})

    def test_appendix_worked_examples_are_current(self):
        rendered = render()
        self.assertEqual(DEFAULT_OUTPUT.read_text(encoding="utf-8"), rendered)
        self.assertEqual(rendered.count(r"\begin{SimpleTable}{PIV Auto Worked Example:"), 10)
        for profile_id in [
            "9a-rsa1024",
            "9e-rsa1024",
            "9a-rsa2048",
            "9e-rsa2048",
            "9a-rsa3072",
            "9e-rsa3072",
            "9a-ecp256",
            "9e-ecp256",
            "9a-ecp384",
            "9e-ecp384",
        ]:
            self.assertIn(rf"\code{{{profile_id}}}", rendered)
        self.assertNotIn("Generated in-memory", rendered)

    def test_committed_report_is_deterministic_and_source_labeled(self):
        report_path = REPO_ROOT / "test-vectors" / "piv-auto-demo" / "generated" / "piv-auto-simulation-report.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertNotIn("generated_at", report["summary"])
        for item in report["profile_coverage"]:
            self.assertNotIn("Generated in-memory", item["source"])
        self.assertEqual(report["poll_response"]["reply"], "osdp_PIVSTATUS")
        for group in [report["poll_response"], *report["multipart_commands"].values()]:
            for fragment in group["fragments"]:
                self.assertEqual(
                    set(fragment),
                    {
                        "message",
                        "message_code",
                        "MpSizeTotal",
                        "MpOffset",
                        "MpFragmentSize",
                        "fragment_data_hex",
                    },
                )

    def test_pivstatusr_preserves_dynamic_authentication_template(self):
        payload = (REPO_ROOT / "test-vectors" / "piv-auto-demo" / "generated" / "pivstatusr-payload.bin").read_bytes()
        signed_response_len = int.from_bytes(payload[53:55], "little")
        signed_response = payload[55:]
        self.assertEqual(len(signed_response), signed_response_len)
        self.assertEqual(signed_response[0], 0x7C)
        fields = parse_dynamic_auth_response(signed_response)
        self.assertEqual(len(fields["82"]), 256)

    def test_vci_importer_fails_when_sources_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "python3",
                    str(REPO_ROOT / "scripts" / "import_vci_vector_fixtures.py"),
                    "--sd33-dir",
                    str(Path(tmp) / "missing-sd33"),
                    "--sm-vci-dir",
                    str(Path(tmp) / "missing-sm-vci"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no VCI vector source files found", result.stderr + result.stdout)

    def test_appendix_worked_examples_segment_short_apdus(self):
        apdu = "0087119A267C2482008120" + ("AA" * 32) + "00"
        self.assertEqual(
            segmented_general_authenticate_apdu(apdu),
            r"\ApduHeader{0087119A}"
            r"\ApduLength{26}"
            r"\ApduTemplate{7C24}"
            r"\ApduResponse{8200}"
            r"\ApduTemplate{8120}"
            + rf"\ApduChallenge{{{'AA' * 32}}}"
            + r"\ApduLength{00}",
        )

    def test_appendix_worked_examples_segment_extended_apdus(self):
        challenge = "BB" * 256
        apdu = "0087079A00010A7C820106820081820100" + challenge + "00"
        segmented = segmented_general_authenticate_apdu(apdu)
        self.assertIn(r"\ApduHeader{0087079A}", segmented)
        self.assertIn(r"\ApduLength{00010A}", segmented)
        self.assertIn(r"\ApduTemplate{7C820106}", segmented)
        self.assertIn(r"\ApduTemplate{81820100}", segmented)
        self.assertIn(rf"\ApduChallenge{{{challenge}}}", segmented)

    def test_appendix_worked_examples_segment_responses(self):
        response_value = "CC" * 70
        response = "7C488246" + response_value + "9000"
        self.assertEqual(
            segmented_dynamic_auth_response(response),
            r"\ApduTemplate{7C48}"
            r"\ApduResponse{8246}"
            + rf"\ApduResponse{{{response_value}}}"
            + r"\ApduStatus{9000}",
        )


if __name__ == "__main__":
    unittest.main()
