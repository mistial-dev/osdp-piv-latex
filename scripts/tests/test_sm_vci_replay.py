"""Wire lifecycle and corruption tests for the capture replay examples."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from check_sm_vci_examples import verify_capture, verify_examples
from sm_vci_replay import ACU, CapturedCard, Peripheral, ROOT, generate, preparation_result, configured_auto_result
from pivdata_simulator import decode_frame, frame

SOURCE = ROOT / "test-vectors/vci-cvc-corpus/vci-contactless-card01/source-vector.json"


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.card = CapturedCard(SOURCE)

    def test_examples(self):
        self.assertGreater(verify_examples(generate()), 30)

    def test_bad_cvc(self):
        v = copy.deepcopy(self.card.vector)
        raw = bytearray.fromhex(v["opacity"]["cvc_raw"])
        raw[-1] ^= 1
        v["opacity"]["cvc_raw"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "CVC signature"):
            verify_capture(v)

    def test_bad_cryptogram(self):
        v = copy.deepcopy(self.card.vector)
        v["opacity"]["auth_cryptogram"] = "00" * 16
        with self.assertRaisesRegex(ValueError, "cryptogram"):
            verify_capture(v)

    def test_bad_rmac(self):
        v = copy.deepcopy(self.card.vector)
        raw = bytearray.fromhex(v["apdu_exchanges"][4]["response"])
        raw[-1] ^= 1
        v["apdu_exchanges"][4]["response"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "response MAC"):
            verify_capture(v)

    def test_bad_crc(self):
        document = generate()
        row = document["examples"][0]["exchanges"][0]
        raw = bytearray.fromhex(row["reply"])
        raw[-1] ^= 1
        row["reply"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "CRC"):
            verify_examples(document)

    def test_repeated_pairing_poll_replays_without_card_attempt(self):
        card = CapturedCard(SOURCE)
        pd = Peripheral(card)
        pd.present_card()
        request = frame(b"\xad00000002", 1)
        self.assertEqual(pd.exchange(request), pd.exchange(request))
        poll = frame(b"\x60", 2)
        reply = pd.exchange(poll)
        count = len(card.events)
        self.assertEqual(reply, pd.exchange(poll))
        self.assertEqual(pd.pairings, 1)
        self.assertEqual(len(card.events), count)

    def test_busy_abort_and_no_late_pairing(self):
        pd = Peripheral(CapturedCard(SOURCE))
        pd.present_card()
        acu = ACU(pd)
        self.assertEqual(acu.send(b"\xad00000002", "pair"), b"\x40")
        self.assertEqual(acu.send(b"\xa9\x01", "busy"), b"\x41\x09")
        self.assertEqual(acu.send(b"\xa2", "abort"), b"\x40")
        self.assertEqual(acu.send(b"\x60", "poll"), b"\x40")
        self.assertEqual(pd.pairings, 0)

    def test_cache_expiry(self):
        pd = Peripheral()
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000100"), "cache")
        acu.send(b"\x60", "complete")
        pd.advance(1)
        pd.present_card()
        acu.send(bytes.fromhex("AA030000000000"), "verify")
        self.assertEqual(acu.send(b"\x60", "expired"), b"\x86\x0a")

    def test_cache_deadline_starts_at_acquisition_not_poll(self):
        pd = Peripheral(interface=1)
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000A00"), "acquire")
        pd.complete_acquisition()
        pd.advance(10)
        self.assertEqual(acu.send(b"\x60", "delayed completion"), b"\x86\x00")
        self.assertIsNone(pd.cached_pin)
        self.assertEqual(pd.expires, 10)
        self.assertEqual(acu.send(bytes.fromhex("AA000000000000"), "state"), b"\x86\x00")

    def test_timeout_default_bounds(self):
        for defaults in ((0, 10), (30, 0), (256, 10), (30, 256)):
            with self.assertRaisesRegex(ValueError, "1 through 255"):
                Peripheral(timeout_defaults=defaults)
        for defaults in ((1, 1), (255, 255)):
            self.assertEqual(Peripheral(timeout_defaults=defaults).timeout_defaults, defaults)

    def test_explicit_timeout_overrides_default(self):
        pd = Peripheral(timeout_defaults=(30, 10))
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040502000A00"), "acquire")
        self.assertEqual(pd.entry_timeouts, (5, 2))
        pd.advance(5)
        self.assertEqual(acu.send(b"\x60", "start timeout"), b"\x86\x01")
        self.assertIsNone(pd.cached_pin)

    def test_inter_key_timeout_uses_selected_default(self):
        pd = Peripheral(timeout_defaults=(30, 10))
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000A00"), "acquire")
        pd.advance(1)
        pd.key_pressed()
        pd.advance(10)
        self.assertEqual(acu.send(b"\x60", "inter-key timeout"), b"\x86\x02")
        self.assertIsNone(pd.cached_pin)

    def test_successful_reuse_does_not_extend_deadline(self):
        pd = Peripheral(interface=1)
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000A00"), "acquire")
        acu.send(b"\x60", "acquired")
        pd.present_card()
        for _ in range(2):
            pd.advance(1)
            acu.send(bytes.fromhex("AA030000000000"), "verify")
            self.assertEqual(acu.send(b"\x60", "result"), b"\x86\x00")
            self.assertEqual(pd.expires, 10)
            self.assertIsNotNone(pd.cached_pin)
        self.assertEqual(acu.send(bytes.fromhex("AA000000000000"), "both"), b"\x86\x03")
        pd.advance(8)
        self.assertEqual(acu.send(bytes.fromhex("AA000000000000"), "verified only"), b"\x86\x02")

    def test_waiting_expiration_has_one_completion(self):
        pd = Peripheral(interface=1)
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000100"), "acquire")
        acu.send(b"\x60", "acquired")
        acu.send(bytes.fromhex("AA030000020000"), "arm")
        self.assertEqual(acu.send(b"\x60", "waiting"), b"\x40")
        pd.advance(1)
        pd.present_card()
        self.assertEqual(acu.send(b"\x60", "expired"), b"\x86\x0a")
        self.assertEqual(acu.send(b"\x60", "finished"), b"\x40")
        self.assertEqual(pd.verifications, 0)

    def test_expiration_submission_boundary(self):
        for submitted in (False, True):
            with self.subTest(submitted=submitted):
                pd = Peripheral(interface=1)
                acu = ACU(pd)
                acu.send(bytes.fromhex("AA040000000100"), "acquire")
                acu.send(b"\x60", "acquired")
                pd.present_card()
                acu.send(bytes.fromhex("AA030000000000"), "verify")
                if submitted:
                    self.assertTrue(pd.submit_pending_verify())
                pd.advance(1)
                self.assertEqual(acu.send(b"\x60", "result"), b"\x86\x00" if submitted else b"\x86\x0a")
                self.assertIsNone(pd.cached_pin)
                self.assertEqual(pd.pin_verified, submitted)

    def test_new_flag_numbers_and_reserved_bits(self):
        acu = ACU(Peripheral())
        self.assertEqual(acu.send(bytes.fromhex("AA040000020100"), "old retain flag"), b"\x41\x09")
        self.assertEqual(acu.send(bytes.fromhex("AA030000080000"), "old auto flag"), b"\x41\x09")
        self.assertEqual(acu.send(bytes.fromhex("AA040000010100"), "retain"), b"\x40")
        acu.send(b"\x60", "acquired")
        acu.pd.remove_card()
        self.assertIsNotNone(acu.pd.cached_pin)

    def test_submitted_verify_transport_failure_has_defined_result(self):
        pd = Peripheral(interface=1)
        pd.present, pd.pin_verified = True, True
        pd.cached_pin, pd.expires = b"123456\xff\xff", 10
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA030000000000"), "verify")
        pd.submit_pending_verify()
        pd.verification_transport_failure()
        self.assertEqual(acu.send(b"\x60", "communication failed"), b"\x86\x0b")
        self.assertFalse(pd.pin_verified)
        self.assertIsNone(pd.cached_pin)
        self.assertTrue(pd.preparation_failed)
        self.assertEqual(acu.send(b"\x60", "no duplicate completion"), b"\x40")

    def test_pairing_timeout_ends_sm_without_retry(self):
        card = CapturedCard(SOURCE)
        pd = Peripheral(card)
        pd.present_card()
        pd.cached_pin, pd.pin_verified = b"123456\xff\xff", True
        acu = ACU(pd)
        self.assertEqual(acu.send(b"\xad00000002", "pair"), b"\x40")
        with patch.object(card, "through", side_effect=TimeoutError) as exchange:
            self.assertEqual(acu.send(b"\x60", "timeout"), bytes.fromhex("8A0200"))
            self.assertEqual(acu.send(b"\x60", "no second result"), b"\x40")
            self.assertEqual(exchange.call_count, 1)
        self.assertEqual(pd.security, 0)
        self.assertTrue(pd.preparation_failed)
        self.assertFalse(pd.pin_verified)
        self.assertIsNone(pd.cached_pin)

    def test_retransmission_after_expiration_does_not_restore_cache(self):
        pd = Peripheral()
        pd.exchange(frame(bytes.fromhex("AA040000000100"), 1))
        poll = frame(b"\x60", 2)
        response = pd.exchange(poll)
        pd.advance(1)
        self.assertEqual(pd.exchange(poll), response)
        self.assertIsNone(pd.cached_pin)
        self.assertEqual(pd.expires, 1)

    def test_verifier_rejects_false_expiration_result(self):
        document = generate()
        example = next(e for e in document["examples"] if e["id"] == "pin-expiration-boundary")
        row = example["exchanges"][-1]
        _, seq, _ = decode_frame(bytes.fromhex(row["reply"]))
        row["reply"] = frame(b"\x86\x00", seq, reply=True).hex().upper()
        with self.assertRaisesRegex(ValueError, "expiration completion"):
            verify_examples(document)

    def test_verifier_rejects_truncated_auto_status_word(self):
        document = generate()
        example = next(e for e in document["examples"] if e["id"] == "auto-status-word")
        example["exchanges"].pop()
        with self.assertRaisesRegex(ValueError, "Auto record length"):
            verify_examples(document)

    def test_verifier_rejects_status_word_on_local_failure_or_timeout(self):
        for result in (7, 8):
            document = generate()
            example = next(e for e in document["examples"] if e["id"] == "auto-status-word")
            row = example["exchanges"][0]
            _, seq, payload = decode_frame(bytes.fromhex(row["reply"]))
            payload = bytearray(payload)
            payload[7] = result
            row["reply"] = frame(bytes(payload), seq, reply=True).hex().upper()
            with self.assertRaisesRegex(ValueError, "local failure or timeout"):
                verify_examples(document)

    def test_verifier_requires_diagnostic_source(self):
        document = generate()
        example = next(e for e in document["examples"] if e["id"] == "diagnostic-cvc-hash")
        example.pop("source")
        with self.assertRaisesRegex(ValueError, "requires a source capture"):
            verify_examples(document)

    def test_cancel_cache(self):
        pd = Peripheral()
        acu = ACU(pd)
        acu.send(bytes.fromhex("AA040000000100"), "cache")
        acu.send(bytes.fromhex("AA050000000000"), "cancel")
        self.assertEqual(acu.send(b"\x60", "poll"), b"\x40")
        self.assertIsNone(pd.cached_pin)

    def test_removal_during_pairing(self):
        pd = Peripheral(CapturedCard(SOURCE))
        pd.present_card()
        acu = ACU(pd)
        acu.send(b"\xad00000002", "pair")
        pd.remove_card()
        self.assertEqual(acu.send(b"\x60", "removed"), bytes.fromhex("8A2610"))

    def test_wrong_sequence(self):
        pd = Peripheral()
        pd.exchange(frame(b"\x60", 1))
        with self.assertRaisesRegex(ValueError, "sequence"):
            pd.exchange(frame(b"\x60", 3))

    def test_no_anchor_does_not_block_9e_eligibility(self):
        self.assertIsNone(preparation_result(requires_pin=False, interface=2,
                                              sm_available=False, pairing_required=True))

    def test_contact_pin_does_not_require_sm(self):
        self.assertIsNone(preparation_result(requires_pin=True, interface=1,
                                              sm_available=False, pairing_required=True))

    def test_contactless_pin_requires_sm_and_pairing(self):
        self.assertEqual(preparation_result(requires_pin=True, interface=2,
                                            sm_available=False, pairing_required=True), (2, 1))
        self.assertEqual(preparation_result(requires_pin=True, interface=2,
                                            sm_available=True, pairing_required=True), (5, 1))
        self.assertIsNone(preparation_result(requires_pin=True, interface=2,
                                              sm_available=True, pairing_required=False))

    def test_validation_failure_stops_even_9e(self):
        self.assertEqual(preparation_result(requires_pin=False, interface=2,
                                            sm_available=False, pairing_required=False,
                                            validation_failed=True), (2, 3))

    def test_different_cached_pin_cannot_reuse_capture(self):
        pd = Peripheral(CapturedCard(SOURCE))
        pd.present_card()
        pd.security = 1
        pd.cached_pin = b"654321\xff\xff"
        pd.pending = ("verify", 2)
        with self.assertRaisesRegex(ValueError, "captured test PIN"):
            pd.execute_pending()

    def test_contactless_mode03_requires_vci(self):
        pd = Peripheral()
        pd.present_card()
        pd.cached_pin = b"123456\xff\xff"
        pd.pending = ("verify", 3)
        self.assertEqual(pd.execute_pending(), b"\x86\x09")

    def test_absent_precedes_vci_error(self):
        pd = Peripheral()
        pd.pending = ("verify", 2)
        self.assertEqual(pd.execute_pending(), b"\x86\x04")

    def test_removed_pin_operation_reports_spe_result(self):
        pd = Peripheral()
        pd.pending = ("verify", 2)
        pd.remove_card()
        self.assertEqual(pd.execute_pending(), b"\x86\x04")

    def test_pairing_is_idempotent_once_vci_established(self):
        pd = Peripheral(CapturedCard(SOURCE))
        pd.present_card()
        pd.security = 1
        pd.pending = ("pair", b"00000002")
        self.assertEqual(pd.execute_pending(), pd.status())
        self.assertEqual(pd.pairings, 0)

    def test_bad_spe_uses_nak(self):
        acu = ACU(Peripheral())
        self.assertEqual(acu.send(b"\xaa", "truncated"), b"\x41\x02")
        self.assertEqual(acu.send(bytes.fromhex("AAFF0000000000"), "unsupported mode"), b"\x41\x09")

    def test_failed_preparation_latch(self):
        pd = Peripheral()
        pd.preparation_failed = True
        with self.assertRaisesRegex(ValueError, "failed preparation"):
            pd.present_card()
        pd.remove_card()
        pd.present_card()

    def test_failed_preparation_blocks_operations(self):
        pd = Peripheral()
        pd.present = True
        pd.security = 1
        pd.cached_pin = b"123456\xff\xff"
        pd.preparation_failed = True
        pd.pending = ("verify", 3)
        self.assertEqual(pd.execute_pending(), b"\x86\x08")
        pd.pending = ("pair", b"00000002")
        self.assertEqual(pd.execute_pending(), bytes.fromhex("8A2310"))

    def test_ga_requires_successful_outer_status(self):
        vector = copy.deepcopy(self.card.vector)
        ga = next(row for row in vector["apdu_exchanges"]
                  if row["command"] == vector["opacity"]["general_authenticate_command"])
        ga["sw"] = "6982"
        with self.assertRaisesRegex(ValueError, "key establishment status"):
            verify_capture(vector)

    def test_blocked_card_status_completes_with_piverror(self):
        pd = Peripheral()
        pd.present = True
        pd.preparation_failed = True
        acu = ACU(pd)
        self.assertEqual(acu.send(bytes.fromhex("A901"), "Card status"), b"\x40")
        self.assertEqual(acu.send(b"\x60", "Poll result"), bytes.fromhex("8A2310"))

    def test_status_does_not_read_discovery_without_sm_or_pin(self):
        card = CapturedCard(ROOT / "test-vectors/vci-cvc-corpus/vci-contactless-card01/source-vector.json")
        pd = Peripheral(card, anchors=False)
        pd.present_card()
        acu = ACU(pd)
        acu.send(bytes.fromhex("A901"), "Card status")
        reply = acu.send(b"\x60", "Poll result")
        self.assertEqual(reply[:5], bytes.fromhex("8501020000"))
        self.assertEqual(reply[21:23], b"\xff\xff")
        self.assertIsNone(pd.pin_policy)

    def test_ga_command_binds_actual_host_key(self):
        vector = copy.deepcopy(self.card.vector)
        op = vector["opacity"]
        ga = next(row for row in vector["apdu_exchanges"] if row["command"] == op["general_authenticate_command"])
        command = bytearray.fromhex(ga["command"])
        position = command.index(bytes.fromhex(op["ephemeral_public_key_x"]))
        command[position] ^= 1
        ga["command"] = op["general_authenticate_command"] = command.hex().upper()
        with self.assertRaisesRegex(ValueError, "host input mismatch"):
            verify_capture(vector)

    def test_pairing_success_requires_protected_success_status(self):
        card = CapturedCard(SOURCE)
        pd = Peripheral(card)
        pd.present_card()
        pd.pending = ("pair", b"00000002")
        with patch.object(card, "through", return_value={"sw": "9000", "response": "99026982"}):
            self.assertEqual(pd.execute_pending(), bytes.fromhex("8A23106982"))
        self.assertEqual(pd.security, 2)
        self.assertFalse(pd.preparation_failed)
        self.assertEqual((pd.sm_outcome, pd.sm_detail), (1, 0))

    def test_pin_success_requires_protected_success_status(self):
        card = CapturedCard(SOURCE)
        pd = Peripheral(card)
        pd.present_card()
        pd.security = 1
        pd.cached_pin = bytes.fromhex(card.vector["sm_session"]["pin_hex"])
        pd.pending = ("verify", 2)
        with patch.object(card, "through", return_value={"sw": "9000", "response": "990263C2"}):
            self.assertEqual(pd.execute_pending(), b"\x86\x03")
        self.assertEqual(pd.verifications, 0)
        self.assertEqual(pd.security, 1)
        self.assertIsNone(pd.cached_pin)
        self.assertFalse(pd.preparation_failed)

    def test_wrong_pairing_preserves_sm_and_diagnostics(self):
        card = CapturedCard(SOURCE)
        pd = Peripheral(card)
        pd.present_card()
        original_hash = pd.cvc_hash
        pd.pending = ("pair", b"00000002")
        with patch.object(card, "through", return_value={"sw": "9000", "response": "99026300"}):
            self.assertEqual(pd.execute_pending(), bytes.fromhex("8A23106300"))
        self.assertEqual(pd.security, 2)
        self.assertEqual((pd.sm_outcome, pd.sm_detail), (1, 0))
        self.assertEqual(pd.cvc_hash, original_hash)
        self.assertFalse(pd.preparation_failed)
        acu = ACU(pd)
        self.assertEqual(acu.send(b"\x60", "no automatic retry"), b"\x40")
        self.assertEqual(pd.pairings, 1)

    def test_pin_rejection_preserves_sm_without_automatic_retry(self):
        pd = Peripheral(interface=2)
        pd.present, pd.security, pd.pin_verified = True, 1, True
        pd.sm_outcome, pd.sm_detail = 1, 0
        pd.cached_pin = b"123456\xff\xff"
        pd.pending = ("submitted", bytes.fromhex("63C2"))
        self.assertEqual(pd.execute_pending(), b"\x86\x03")
        self.assertEqual(pd.security, 1)
        self.assertFalse(pd.pin_verified)
        self.assertIsNone(pd.cached_pin)
        self.assertEqual((pd.sm_outcome, pd.sm_detail), (1, 0))
        self.assertEqual(ACU(pd).send(b"\x60", "no automatic retry"), b"\x40")

    def test_protected_status_rejects_failed_outer_status(self):
        with self.assertRaisesRegex(ValueError, "outer status"):
            CapturedCard.protected_status({"sw": "6982", "response": "99029000"})

    def test_sm_failure_preserves_diagnostics_and_blocks_status(self):
        pd = Peripheral(self.card)
        pd.present_card()
        original_hash = pd.cvc_hash
        pd.cached_pin = b"123456\xff\xff"
        pd.fail_sm()
        self.assertEqual(pd.status(), bytes.fromhex("8A2310"))
        self.assertEqual(pd.cvc_hash, original_hash)
        self.assertIsNone(pd.cached_pin)
        self.assertEqual((pd.sm_outcome, pd.sm_detail), (3, 6))

    def test_unimplemented_spe_modes_do_not_emit_length_error(self):
        for mode in (1, 6):
            with self.subTest(mode=mode):
                pd = Peripheral()
                with self.assertRaisesRegex(ValueError, "outside replay scope"):
                    pd.exchange(frame(bytes([0xAA, mode, 0, 0, 0, 0, 0]), 1))

    def test_diagnostic_hash_after_failure_without_credential_io(self):
        pd = Peripheral(self.card)
        pd.present = pd.preparation_failed = True
        pd.sm_outcome, pd.sm_detail = 3, 4
        cvc = bytes.fromhex(self.card.vector["opacity"]["cvc_raw"])
        pd.cvc_hash = hashlib.sha256(cvc).digest()
        acu = ACU(pd)
        with patch.object(self.card, "through", side_effect=AssertionError("credential accessed")):
            self.assertEqual(acu.send(bytes.fromhex("A902"), "Diagnostic"), b"\x40")
            record = bytearray()
            while pd.pending:
                reply = acu.send(b"\x60", "Read diagnostic")
                self.assertEqual(reply[:4], bytes.fromhex("85022300"))
                self.assertEqual(int.from_bytes(reply[4:6], "little"), len(record))
                self.assertEqual(int.from_bytes(reply[6:8], "little"), len(reply) - 8)
                record.extend(reply[8:])
        self.assertEqual(record, bytes([3, 4, 1]) + hashlib.sha256(cvc).digest())
        self.assertNotIn(cvc, record)

    def test_diagnostic_no_cvc_received(self):
        pd = Peripheral(anchors=False)
        pd.present_card()
        pd.diagnostic_fragment_size = 35
        acu = ACU(pd)
        acu.send(bytes.fromhex("A902"), "Diagnostic")
        self.assertEqual(acu.send(b"\x60", "Read diagnostic")[8:], bytes([2, 1, 0]) + bytes(32))

    def test_status_type_selects_layout_and_rejects_mismatch(self):
        for bad_type in (1, 3):
            pd = Peripheral()
            acu = ACU(pd)
            acu.send(bytes.fromhex("A902"), "diagnostic")
            acu.send(b"\x60", "first fragment")
            self.assertTrue(acu.diagnostic)
            wrong = bytes([0x85, bad_type]) + bytes(22)
            with patch.object(pd, "exchange", return_value=frame(wrong, acu.sequence, reply=True)):
                with self.assertRaisesRegex(ValueError, "type"):
                    acu.send(b"\x60", "wrong type")
            self.assertEqual(acu.diagnostic, b"")

    def test_absent_credential_status_has_standard_type(self):
        pd = Peripheral()
        acu = ACU(pd)
        acu.send(bytes.fromhex("A901"), "standard status")
        reply = acu.send(b"\x60", "absent credential")
        self.assertEqual(reply, b"\x85\x01" + bytes(19) + b"\xff\xff\x00")

    def test_cached_pin_modes_distinguish_contact_from_vci(self):
        for mode, expected in ((2, b"\x86\x09"), (3, b"\x86\x00")):
            pd = Peripheral(interface=1)
            pd.present, pd.security = True, 2
            pd.cached_pin, pd.expires = b"123456\xff\xff", 10
            acu = ACU(pd)
            self.assertEqual(acu.send(bytes([0xAA, mode, 0, 0, 0, 0, 0]), "verify"), b"\x40")
            self.assertEqual(acu.send(b"\x60", "result"), expected)

    def test_independent_verifier_rejects_wrong_status_type(self):
        document = generate()
        example = next(e for e in document["examples"] if e["id"] == "diagnostic-cvc-hash")
        row = example["exchanges"][-1]
        _, seq, payload = decode_frame(bytes.fromhex(row["reply"]))
        row["reply"] = frame(payload[:1] + b"\x01" + payload[2:], seq, reply=True).hex()
        with self.assertRaisesRegex(ValueError, "diagnostic reply type"):
            verify_examples(document)

    def test_diagnostic_poll_retransmission_preserves_fragment(self):
        pd = Peripheral()
        pd.exchange(frame(bytes.fromhex("A902"), 1))
        poll = frame(b"\x60", 2)
        first = pd.exchange(poll)
        self.assertEqual(pd.exchange(poll), first)
        self.assertEqual(pd.pending[1][1], 16)

    def test_diagnostic_removal_terminates_transfer(self):
        pd = Peripheral()
        pd.present = True
        acu = ACU(pd)
        acu.send(bytes.fromhex("A902"), "Diagnostic")
        acu.send(b"\x60", "First fragment")
        pd.remove_card()
        self.assertEqual(acu.send(b"\x60", "Removal error"), bytes.fromhex("8A2610"))
        self.assertIsNone(pd.cvc_hash)
        self.assertEqual(pd.sm_outcome, 0)

    def test_diagnostic_abort_and_competing_request(self):
        pd = Peripheral()
        acu = ACU(pd)
        acu.send(bytes.fromhex("A902"), "Diagnostic")
        self.assertEqual(acu.send(bytes.fromhex("A901"), "Competing status"), b"\x41\x09")
        self.assertEqual(acu.send(b"\xa2", "Abort"), b"\x40")
        self.assertEqual(acu.send(b"\x60", "No remaining fragments"), b"\x40")

    def test_required_vci_unsupported(self):
        self.assertEqual(preparation_result(requires_pin=True, interface=2,
                         sm_available=True, pairing_required=False, vci_supported=False), (5, 3))

    def test_configured_9a_prerequisites(self):
        cases = (
            ({"sm_available": False}, (2, 1)),
            ({"vci_supported": False}, (5, 3)),
            ({"pairing_required": True}, (5, 1)),
            ({}, (5, 2)),
            ({"pin_verified": True}, None),
            ({"occ_verified": True}, None),
            ({"validation_failed": True, "pin_verified": True}, (2, 3)),
        )
        for changes, expected in cases:
            with self.subTest(changes=changes):
                config = dict(key_reference=0x9A, interface=2, sm_available=True,
                              pairing_required=False)
                config.update(changes)
                self.assertEqual(configured_auto_result(**config), expected)

    def test_configured_9e_and_contact_9a(self):
        self.assertIsNone(configured_auto_result(key_reference=0x9E, interface=2,
                          sm_available=False, pairing_required=True))
        self.assertEqual(configured_auto_result(key_reference=0x9A, interface=1,
                         sm_available=False, pairing_required=True), (5, 2))
        self.assertIsNone(configured_auto_result(key_reference=0x9A, interface=1,
                          sm_available=False, pairing_required=True, pin_verified=True))

    def test_reserved_status_type_reports_invalid_parameter(self):
        acu = ACU(Peripheral())
        self.assertEqual(acu.send(bytes.fromhex("A903"), "Reserved status type"), b"\x40")
        self.assertEqual(acu.send(b"\x60", "Invalid parameter"), bytes.fromhex("8A0500"))

    def test_independent_verifier_rejects_wrong_diagnostic_hash(self):
        document = generate()
        example = next(e for e in document["examples"] if e["id"] == "diagnostic-cvc-hash")
        row = example["exchanges"][-1]
        _, seq, payload = decode_frame(bytes.fromhex(row["reply"]))
        changed = payload[:-1] + bytes([payload[-1] ^ 1])
        row["reply"] = frame(changed, seq, reply=True).hex().upper()
        with self.assertRaisesRegex(ValueError, "CVC hash mismatch"):
            verify_examples(document)


if __name__ == "__main__":
    unittest.main()
