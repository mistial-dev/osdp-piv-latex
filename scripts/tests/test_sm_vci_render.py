"""Keep the printed packet examples tied to independently checked exchanges."""
import json
import unittest

from render_sm_vci_examples import ROOT, OUTPUT, render


class RenderingTests(unittest.TestCase):
    def test_checked_in_tables_are_current(self):
        source = json.loads((ROOT / "worked-examples/sm-vci/examples.json").read_text())
        self.assertEqual(OUTPUT.read_text(), render(source))

    def test_packet_hex_and_error_meaning_are_visible(self):
        output = OUTPUT.read_text()
        self.assertIn("Packet bytes (hex)", output)
        self.assertIn("53 01", output)
        self.assertNotIn("0x53 0x01", output)
        self.assertIn("Result 0x05, Detail 0x01: pairing code required", output)
        self.assertIn("SM established without VCI", output)
        self.assertIn("Result 0x02, Detail 0x04: invalid authentication cryptogram", output)
        self.assertIn("Diagnostic: total 0x0023, offset 0x0010, fragment 0x0010", output)


if __name__ == "__main__":
    unittest.main()
