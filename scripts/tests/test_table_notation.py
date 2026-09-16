"""Keep protocol table sizes hexadecimal and multipart headers consistent."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TableNotationTests(unittest.TestCase):
    def test_packet_sizes_are_hexadecimal(self):
        count = 0
        for path in (ROOT / "tables").glob("osdp-*.tex"):
            for size in re.findall(r"\\PacketRow\{([^}]+)\}", path.read_text()):
                count += 1
                self.assertRegex(size, r"^0x[0-9A-F]+(?:(?:-| or )(?:0x[0-9A-F]+|n))?$", path.name)
        self.assertGreater(count, 100)

    def test_multipart_fields_precede_logical_payload(self):
        names = ("crauth", "crauthr", "pivdata", "pivdatar", "pivputdata",
                 "pivmode", "pivstatusr", "vciloatda", "vcitastatus", "sm-diagnostic")
        for name in names:
            text = (ROOT / f"tables/osdp-{name}.tex").read_text()
            fields = re.findall(r"\\PacketRow\{[^}]+\}\{([^}]+)\}", text)
            if "MpSizeTotal" in fields:
                prefix = ["CMND", "Status Type"] if name == "sm-diagnostic" else ["CMND"]
                expected = prefix + ["MpSizeTotal", "MpOffset", "MpFragmentSize"]
                self.assertEqual(fields[:len(expected)], expected, name)

    def test_no_decimal_byte_sizes_in_table_rows(self):
        for path in [*(ROOT / "tables").glob("*.tex"), *(ROOT / "sections").glob("*.tex")]:
            for line in path.read_text().splitlines():
                if " & " in line or r"\PacketRow{" in line:
                    self.assertNotRegex(line, r"(?<![\w])\d+(?:-byte| bytes?\b| octets?\b)", path.name)

    def test_status_reply_layouts_keep_code_and_expose_type(self):
        for name, status_type in (("cardstatusr", "0x01"), ("sm-diagnostic", "0x02")):
            text = (ROOT / f"tables/osdp-{name}.tex").read_text()
            rows = [line for line in text.splitlines() if r"\PacketRow{" in line]
            self.assertIn("{0x85 (tentative)}", rows[0])
            self.assertIn("{Status Type}", rows[1])
            self.assertTrue(rows[1].endswith("{" + status_type + "}"))
