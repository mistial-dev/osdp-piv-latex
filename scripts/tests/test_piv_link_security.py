import unittest

from piv_link_security import Channel, ChannelRequired, ProtectedTransfer, protected_operation


class PivLinkSecurityTests(unittest.TestCase):
    def test_tpk_matching_and_every_match_reply_require_channel(self):
        for command in [0xAC, 0xAB, 0x87]:
            self.assertTrue(protected_operation(command))
        good = Channel("session-a", "3.0", True)
        good.require(True)
        for channel, protected in [(Channel(), False), (good, False),
                                   (Channel("session-a", "2.0", True), True),
                                   (Channel("session-a", "3.0", False), True)]:
            with self.subTest(channel=channel, protected=protected):
                with self.assertRaises(ChannelRequired) as caught:
                    ProtectedTransfer.begin(channel, protected)
                self.assertEqual(caught.exception.code, 0x0006)

    def test_biometric_object_aliases_are_protected(self):
        for model, objects in [(1, ["5FC103", "5FC108", "5FC121", "6010", "6030", "1015"]),
                               (2, ["DFC001", "DFC002", "DFC101", "DFC103", "DFC108",
                                    "DFC109", "DFC121", "6011", "6012", "2001", "2003",
                                    "6030", "3001", "1015"])]:
            for identifier in objects:
                for command in [0xA3, 0x80]:
                    with self.subTest(model=model, identifier=identifier, command=command):
                        self.assertTrue(protected_operation(command, model, bytes.fromhex(identifier)))
        # A public authentication certificate has a different identity from the TPK object.
        self.assertFalse(protected_operation(0xA3, 2, bytes.fromhex("5FC101")))
        self.assertFalse(protected_operation(0xA3, 1, bytes.fromhex("0102")))

    def test_clear_poll_never_releases_biometric_fragment_or_replay(self):
        channel = Channel("session-a", "3.0", True)
        transfer = ProtectedTransfer.begin(channel, True)
        transfer.pending.extend(b"encrypted biometric data")
        self.assertEqual(transfer.release(channel, True, 4), b"encr")
        with self.assertRaises(ChannelRequired):
            transfer.release(channel, False, 5)
        self.assertEqual(transfer.pending, bytearray())
        self.assertEqual(transfer.replay, b"")
        with self.assertRaises(ChannelRequired):
            transfer.release(channel, True, 5)

    def test_loss_or_replacement_clears_key_data_and_replay(self):
        original = Channel("session-a", "3.0", True)
        for replacement in [Channel(), Channel("session-b", "3.0", True),
                            Channel("session-a", "3.0", False)]:
            with self.subTest(replacement=replacement):
                transfer = ProtectedTransfer.begin(original, True)
                transfer.tpk.extend(b"sensitive key")
                transfer.pending.extend(b"sensitive biometric data")
                transfer.release(original, True, 3)
                with self.assertRaises(ChannelRequired):
                    transfer.release(replacement, True, 4)
                self.assertFalse(transfer.active)
                self.assertEqual(transfer.tpk, bytearray())
                self.assertEqual(transfer.pending, bytearray())
                self.assertEqual(transfer.replay, b"")
                with self.assertRaises(ChannelRequired):
                    transfer.release(original, True, 4)
                new_transfer = ProtectedTransfer.begin(Channel("new-session", "3.0", True), True)
                self.assertTrue(new_transfer.active)
