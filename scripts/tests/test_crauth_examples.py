"""CRAUTH format recognition, multipart boundaries, and terminal errors."""
import copy
import json
import unittest

from crauth_examples import Controller, Peripheral, ROOT, OUTPUT, generate, multipart, request_format
from check_crauth_examples import verify
from pivdata_simulator import decode_frame, frame
from render_crauth_examples import render


class CrauthTests(unittest.TestCase):
    def test_marker_classification(self):
        self.assertEqual(request_format(b"\xff"), "3.0")
        for algorithm in (0, 3, 5, 6, 7, 8, 10, 12, 17, 20, 39, 46):
            self.assertEqual(request_format(bytes([algorithm])), "2.2")
        with self.assertRaises(ValueError):
            request_format(b"")

    def test_every_prefix_boundary_and_ff_in_challenge(self):
        record = bytes.fromhex("FF119EFF0001")
        for split in range(1, len(record)):
            pd = Peripheral(record, b"\x7c\x00")
            self.assertEqual(pd.command(multipart(0xA5, record, 0, split)), b"\x40")
            self.assertEqual(pd.credential_calls, 0)
            self.assertEqual(pd.command(multipart(0xA5, record, split, len(record))), b"\x40")
            self.assertEqual(pd.credential_calls, 1)
            self.assertEqual(pd.command(b"\x60")[7:], b"\x7c\x00")

    def test_legacy_rejected_by_new_only_pd(self):
        pd = Peripheral(bytes.fromhex("FF119E00"), b"")
        self.assertEqual(pd.command(multipart(0xA5, bytes.fromhex("119E00"), 0, 3)), b"\x41\x09")
        self.assertEqual(pd.credential_calls, 0)

    def test_invalid_record_never_falls_back(self):
        pd = Peripheral(bytes.fromhex("FF119E00"), b"")
        self.assertEqual(pd.command(multipart(0xA5, bytes.fromhex("FF119E"), 0, 3)), b"\x40")
        self.assertEqual(pd.command(b"\x60"), bytes.fromhex("8A0500"))
        self.assertEqual(pd.credential_calls, 0)

    def test_fragment_gap_rejected_and_abort_resets(self):
        record = bytes.fromhex("FF119E00")
        pd = Peripheral(record, b"")
        self.assertEqual(pd.command(multipart(0xA5, record, 0, 1)), b"\x40")
        self.assertEqual(pd.command(multipart(0xA5, record, 2, 2)), b"\x41\x09")
        self.assertEqual(pd.command(b"\xa2"), b"\x40")
        self.assertEqual(pd.command(multipart(0xA5, record, 0, len(record))), b"\x40")

    def test_retransmission_does_not_repeat_execution(self):
        record = bytes.fromhex("FF119E00")
        pd = Peripheral(record, b"\x7c\x00")
        packet = frame(multipart(0xA5, record, 0, len(record)), 1)
        self.assertEqual(pd.exchange(packet), pd.exchange(packet))
        self.assertEqual(pd.credential_calls, 1)
        poll = frame(b"\x60", 2)
        self.assertEqual(pd.exchange(poll), pd.exchange(poll))

    def test_terminal_error_discards_partial_reply(self):
        acu = Controller()
        acu.receive(multipart(0x82, b"\x7c\x02\x82\x00", 0, 2))
        acu.receive(bytes.fromhex("8A0200"))
        self.assertTrue(acu.done)
        self.assertEqual(acu.error, 2)
        self.assertEqual(acu.data, b"")

    def assert_transaction_cleared(self, pd):
        self.assertEqual(pd.data, b"")
        self.assertIsNone(pd.total)
        self.assertFalse(pd.ready)
        self.assertEqual(pd.offset, 0)
        self.assertIsNone(pd.pending_error)

    def test_consecutive_successful_requests_restart_at_zero(self):
        record = bytes.fromhex("FF119E00")
        response = b"\x7c" + bytes(80)
        pd = Peripheral(record, response)
        for attempt in range(2):
            self.assertEqual(pd.command(multipart(0xA5, record, 0, len(record))), b"\x40")
            acu = Controller()
            offsets = []
            while not acu.done:
                reply = pd.command(b"\x60")
                offsets.append(int.from_bytes(reply[3:5], "little"))
                acu.receive(reply)
            self.assertEqual(offsets, [0, 40, 80])
            self.assertEqual(acu.data, response)
            self.assertEqual(pd.credential_calls, attempt + 1)
            self.assert_transaction_cleared(pd)
            self.assertEqual(pd.command(b"\x60"), b"\x40")

    def test_invalid_request_recovery_with_and_without_abort(self):
        record = bytes.fromhex("FF119E00")
        for abort, deliver_error in ((False, True), (True, True), (True, False)):
            with self.subTest(abort=abort, deliver_error=deliver_error):
                pd = Peripheral(record, b"\x7c\x00")
                invalid = bytes.fromhex("FF119EFF")
                pd.command(multipart(0xA5, invalid, 0, len(invalid)))
                if deliver_error:
                    self.assertEqual(pd.command(b"\x60"), bytes.fromhex("8A0500"))
                    self.assert_transaction_cleared(pd)
                if abort:
                    self.assertEqual(pd.command(b"\xa2"), b"\x40")
                    self.assert_transaction_cleared(pd)
                self.assertEqual(pd.command(multipart(0xA5, record, 0, len(record))), b"\x40")
                self.assertEqual(pd.command(b"\x60"), multipart(0x82, b"\x7c\x00", 0, 2))
                self.assertEqual(pd.credential_calls, 1)
                self.assert_transaction_cleared(pd)

    def test_validation_error_does_not_replace_injected_failure(self):
        record = bytes.fromhex("FF119E00")
        fixture_error = bytes.fromhex("8A23106982")
        pd = Peripheral(record, b"\x7c\x00", fixture_error, fail_after_data=True)
        invalid = bytes.fromhex("FF119EFF")
        pd.command(multipart(0xA5, invalid, 0, len(invalid)))
        self.assertEqual(pd.command(b"\x60"), bytes.fromhex("8A0500"))
        self.assertEqual(pd.failure, fixture_error)
        self.assert_transaction_cleared(pd)

    def test_terminal_credential_error_recovery_and_retransmission(self):
        record = bytes.fromhex("FF119E00")
        fixture_error = bytes.fromhex("8A23106982")
        pd = Peripheral(record, b"\x7c\x00", fixture_error)
        pd.exchange(frame(multipart(0xA5, record, 0, len(record)), 1))
        poll = frame(b"\x60", 2)
        reply = pd.exchange(poll)
        self.assertEqual(decode_frame(reply)[2], fixture_error)
        self.assertEqual(pd.exchange(poll), reply)
        self.assert_transaction_cleared(pd)
        pd.failure = None  # The fake credential accepts the next operation.
        pd.exchange(frame(multipart(0xA5, record, 0, len(record)), 3))
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 1)))[2],
                         multipart(0x82, b"\x7c\x00", 0, 2))
        self.assertEqual(pd.credential_calls, 2)

    def test_final_reply_replay_then_new_request(self):
        record = bytes.fromhex("FF119E00")
        pd = Peripheral(record, b"\x7c\x00")
        pd.exchange(frame(multipart(0xA5, record, 0, len(record)), 1))
        poll = frame(b"\x60", 2)
        reply = pd.exchange(poll)
        self.assert_transaction_cleared(pd)
        self.assertEqual(pd.exchange(poll), reply)
        self.assertEqual(pd.credential_calls, 1)
        self.assertEqual(decode_frame(pd.exchange(
            frame(multipart(0xA5, record, 0, len(record)), 3)))[2], b"\x40")
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 1)))[2],
                         multipart(0x82, b"\x7c\x00", 0, 2))
        self.assertEqual(pd.credential_calls, 2)

    def test_generated_examples_and_tables_are_current(self):
        document = generate()
        self.assertEqual(document, json.loads(OUTPUT.read_text()))
        self.assertEqual(verify(document), 28)
        self.assertEqual((ROOT / "tables/crauth-worked-examples.tex").read_text(), render(document))

    def test_independent_checker_rejects_bad_marker(self):
        document = copy.deepcopy(generate())
        document["record"] = "FE" + document["record"][2:]
        with self.assertRaisesRegex(ValueError, "marker"):
            verify(document)

    def test_independent_checker_rejects_bad_crc(self):
        document = generate()
        row = document["cases"][0]["exchanges"][0]
        row["request"] = row["request"][:-5] + "00 00"
        with self.assertRaisesRegex(ValueError, "CRC"):
            verify(document)

    def test_independent_checker_rejects_marker_forwarded_to_credential(self):
        document = generate()
        document["credential_command"] = "FF" + document["credential_command"]
        with self.assertRaisesRegex(ValueError, "marker leaked"):
            verify(document)
