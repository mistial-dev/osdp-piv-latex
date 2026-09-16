import re
import unittest

from render_pivdata_examples import frame_lines, reply_notes, request_table


class ExampleTableTests(unittest.TestCase):
    def test_identifiers_and_tags_are_single_hex_values(self):
        table = request_table("A3035FC102025F2F00000000")
        self.assertIn(r"Object Identifier & \texttt{0x5FC102}", table)
        self.assertIn(r"Element Tag & \texttt{0x5F2F}", table)
        self.assertNotIn("0x5F 0xC1 0x02", table)

    def test_request_fields_are_hex_with_notes(self):
        table = request_table("A3017E0000010401")
        self.assertIn(r"\TableHeaderCell{Notes}", table)
        self.assertIn(r"\texttt{0xA3}", table)
        self.assertIn(r"Offset & \texttt{0x0100}", table)
        self.assertIn(r"Requested Length & \texttt{0x0104}", table)
        self.assertIn("Element Tag & Omitted", table)

    def test_short_frame_keeps_every_byte(self):
        packet = "5381080005403935"
        rendered = " ".join(frame_lines(packet))
        self.assertNotIn("0x", rendered)
        values = re.findall(r"\b[0-9A-F]{2}\b", rendered)
        self.assertEqual("".join(values), packet)

    def test_long_frame_keeps_ends_and_reports_omission(self):
        packet = bytes(range(128))
        rows = frame_lines(packet.hex())
        self.assertIn("... 0x58 bytes omitted ...", rows)
        shown = " ".join(row for row in rows if "omitted" not in row)
        self.assertNotIn("0x", shown)
        self.assertEqual(bytes(int(x, 16) for x in shown.split()),
                         packet[:24] + packet[-16:])

    def test_reply_notes_decode_hex_fields_and_error_meanings(self):
        name, notes = reply_notes("53810E0006800401720072000000")
        self.assertEqual(name, "PIVGETDATAR")
        self.assertIn("0x0104", notes)
        self.assertEqual(notes.count("0x0072"), 2)
        name, notes = reply_notes("53810A00068A24100000")
        self.assertEqual(name, "PIVERROR")
        self.assertIn("0x1024", notes)
        self.assertIn("data object or tag not found", notes)
