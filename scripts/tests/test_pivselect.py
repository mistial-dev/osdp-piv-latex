"""Synthetic PIVSELECT payload/context cases, with no credential or hardware I/O."""
from pathlib import Path
import unittest

from pivselect_examples import PIV_AID, TWIC_PREFIX, Peripheral, Request, SelectionError

ROOT = Path(__file__).resolve().parents[2]


def payload(model, aid):
    return bytes([0xB0, 0, model, len(aid)]) + aid


class PivSelectTests(unittest.TestCase):
    def test_printed_examples_match_layout(self):
        source = (ROOT / "sections/04-new-commands.tex").read_text()
        for model, aid, literal in (
            (1, PIV_AID, "B0 00 01 0B A0 00 00 03 08 00 00 10 00 01 00"),
            (2, TWIC_PREFIX, "B0 00 02 09 A0 00 00 03 67 20 00 00 01"),
        ):
            self.assertEqual(payload(model, aid), bytes.fromhex(literal))
            self.assertEqual(Request.decode(bytes.fromhex(literal)), Request(model, aid))
            self.assertIn(r"\texttt{" + literal + "}", source)

    def test_packet_table_has_model_before_aid_length(self):
        source = (ROOT / "tables/osdp-pivselect.tex").read_text()
        self.assertLess(source.index("{Selection Flags}"), source.index("{Data Model}"))
        self.assertLess(source.index("{Data Model}"), source.index("{AID Length}"))

    def test_all_public_models_and_size_boundaries(self):
        for model in (1, 2, 3):
            for size in (5, 16):
                aid = bytes(range(size))
                packet = payload(model, aid)
                self.assertEqual(len(packet), 4 + size)
                self.assertEqual(Request.decode(packet), Request(model, aid))

    def test_bad_requests_do_not_touch_credential_or_context(self):
        good = payload(1, PIV_AID)
        invalid = [b"", good[:-1], good + b"\x00",
                   bytes([0xB0, 1]) + good[2:],
                   bytes([0xB0, 0, len(PIV_AID)]) + PIV_AID]
        invalid += [payload(model, PIV_AID) for model in (0, 4, 0x7F, 0x80, 0xFF)]
        invalid += [payload(1, bytes(size)) for size in (0, 4, 17)]
        for packet in invalid:
            with self.subTest(packet=packet.hex()):
                pd = Peripheral()
                pd.model, pd.aid = 2, TWIC_PREFIX
                pd.security["pin_verified"] = True
                with self.assertRaises(SelectionError) as caught:
                    pd.select(packet, lambda aid: self.fail("credential SELECT was issued"))
                self.assertEqual(caught.exception.code, 0x0005)
                self.assertEqual(pd.credential_calls, 0)
                self.assertEqual((pd.model, pd.aid), (2, TWIC_PREFIX))
                self.assertEqual(pd.security, {"pin_verified": True})

    def test_private_models_require_explicit_support(self):
        packet = payload(0x80, PIV_AID)
        self.assertEqual(Request.decode(packet, (0x80,)), Request(0x80, PIV_AID))

    def test_success_needs_no_profile_and_retains_mode_settings(self):
        pd = Peripheral()
        pd.interface, pd.mode_flags = "contactless", 2
        for suffix in ("0101", "0103"):
            actual = TWIC_PREFIX + bytes.fromhex(suffix)
            self.assertEqual(pd.select(payload(2, TWIC_PREFIX), lambda aid: actual), b"\x40")
            self.assertEqual((pd.model, pd.aid), (2, actual))
            self.assertEqual((pd.interface, pd.mode_flags), ("contactless", 2))

    def test_success_without_fci_uses_requested_aid(self):
        pd = Peripheral()
        pd.select(payload(2, TWIC_PREFIX), lambda aid: None)
        self.assertEqual((pd.model, pd.aid), (2, TWIC_PREFIX))

    def test_credential_failure_preserves_previous_context(self):
        pd = Peripheral()
        pd.model, pd.aid = 1, PIV_AID
        pd.security.update(sm=True, pin_verified=True)
        def reject(aid):
            raise SelectionError("AID absent", 0x1024)
        with self.assertRaises(SelectionError) as caught:
            pd.select(payload(2, TWIC_PREFIX), reject)
        self.assertEqual(caught.exception.code, 0x1024)
        self.assertEqual((pd.model, pd.aid), (1, PIV_AID))
        self.assertEqual(pd.security, {"sm": True, "pin_verified": True})

    def test_same_context_preserves_security_changes_clear_it(self):
        pd = Peripheral()
        pd.model, pd.aid = 1, PIV_AID
        pd.security.update(sm=True, pin_verified=True)
        pd.select(payload(1, PIV_AID), lambda aid: PIV_AID)
        self.assertEqual(pd.security, {"sm": True, "pin_verified": True})
        pd.select(payload(3, PIV_AID), lambda aid: PIV_AID)
        self.assertEqual(pd.security, {})
        pd.security["pin_verified"] = True
        pd.select(payload(2, TWIC_PREFIX), lambda aid: TWIC_PREFIX + b"\x01\x03")
        self.assertEqual(pd.security, {})

    def test_first_piv_selection_keeps_precollected_pin(self):
        pd = Peripheral()
        pd.security["cached_pin"] = "synthetic test PIN"
        pd.select(payload(1, PIV_AID), lambda aid: PIV_AID)
        self.assertEqual(pd.security, {"cached_pin": "synthetic test PIN"})
