"""Wire, selection and transaction tests for the proposed PIVGETDATA revision."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pivdata_simulator import (Controller, PIVError, Peripheral, Request, crc16, decode_frame,
                              frame, select_response, valid_tag, getdata_format)
from check_pivdata_examples import check
from generate_pivdata_examples import generate, DIRECTORY


class SelectionTests(unittest.TestCase):
    def error(self, code, request, response):
        with self.assertRaises(PIVError) as caught:
            select_response(request, bytes.fromhex(response))
        self.assertEqual(code, caught.exception.code)

    def test_identifier_and_wire(self):
        request = Request(bytes.fromhex("7F61"), bytes.fromhex("7F60"), 256, 258)
        self.assertEqual(request.encode().hex(), "a3027f61027f6000010201")
        self.assertEqual(Request.decode(request.encode()), request)
        for invalid in ("", "00", "FF", "7F", "7F80", "7F8100FF", "3001"):
            self.assertFalse(valid_tag(bytes.fromhex(invalid)), invalid)
        for wire in (b"", bytes.fromhex("a30000000000"), request.encode() + b"\x00"):
            with self.assertRaises(PIVError):
                Request.decode(wire)

    def test_complete_elements_and_not_recursive(self):
        request = Request(b"\x7e", bytes.fromhex("5f2f"))
        self.assertEqual(select_response(request, bytes.fromhex("7e055f2f024800")), bytes.fromhex("5f2f024800"))
        self.error(0x1024, Request(b"\x7e", b"\x30"), "7e05a1033001ff")
        self.error(0x1027, Request(b"\x7e", b"\x30"), "7e063001aa3001bb")
        self.error(0x1028, request, "7e065f2f024800")
        self.error(0x1028, request, "7e805f2f0248000000")
        self.error(0x1028, request, "7e055f2f024800ff")
        self.error(0x1028, Request(b"\x7e", b"\x30"), "7e063001aa3105bb")

    def test_bounds_and_empty(self):
        data = bytes.fromhex("53033001aa")
        self.assertEqual(select_response(Request(b"\x7e", offset=5), data), b"")
        self.assertEqual(select_response(Request(b"\x7e", offset=1, requested=2), data), data[1:3])
        self.error(5, Request(b"\x7e", offset=6), data.hex())
        self.assertEqual(select_response(Request(b"\x7e", offset=4, requested=2), data), b"\xaa")
        self.assertEqual(select_response(Request(b"\x7e", offset=5, requested=2), data), b"")
        self.assertEqual(select_response(Request(b"\x7e"), b"\xff\x00"), b"\xff\x00")
        self.assertEqual(select_response(Request(b"\x7e"), b""), b"")
        self.assertEqual(select_response(Request(b"\x7e"), b"\x53\x00"), b"\x53\x00")

    def test_capacity_boundary(self):
        maximum = b"\x53\x82\xff\xfb" + bytes(65531)
        too_large = b"\x53\x82\xff\xfc" + bytes(65532)
        self.assertEqual(len(select_response(Request(b"\x7e"), maximum)), 65535)
        self.error(0x1029, Request(b"\x7e"), too_large.hex())
        self.assertEqual(len(select_response(Request(b"\x7e", requested=100), too_large)), 100)

    def test_long_unselected_tag_and_private_selector(self):
        self.assertTrue(valid_tag(bytes.fromhex("FF20")))
        data = bytes.fromhex("53095F81810100FF2001AA")
        self.assertEqual(select_response(Request(b"\x7e", bytes.fromhex("FF20")), data), bytes.fromhex("FF2001AA"))

    def test_child_header_preserved_and_range_relative_to_tag(self):
        data = bytes.fromhex("5306308101AA3400")
        self.assertEqual(select_response(Request(b"\x7e", b"\x30"), data), bytes.fromhex("308101AA"))
        self.assertEqual(select_response(Request(b"\x7e", b"\x30", 3, 1), data), b"\xaa")
        self.assertEqual(select_response(Request(b"\x7e", b"\x30", 4, 1), data), b"")
        self.error(5, Request(b"\x7e", b"\x30", 5), data.hex())
        self.assertEqual(select_response(Request(b"\x7e", b"\x34"), data), bytes.fromhex("3400"))
        self.assertEqual(select_response(Request(b"\x7e", b"\x34", 2), data), b"")


class WireTests(unittest.TestCase):
    def test_format_classification_uses_disjoint_lengths(self):
        self.assertEqual(getdata_format(bytes.fromhex("A35FC1023000")), "2.2")
        for identifier in (b"\x7e", bytes.fromhex("7F61"), bytes.fromhex("5FC102")):
            for tag in (b"", b"\x30", bytes.fromhex("5F2F"), bytes.fromhex("5F8101")):
                request = Request(identifier, tag).encode()
                self.assertEqual(getdata_format(request), "3.0")
                self.assertEqual(Request.decode(request).encode(), request)
        for size in (0, 1, 2, 3, 4, 6, 13):
            with self.assertRaises(PIVError):
                getdata_format(b"\xa3" + bytes(size))
        with self.assertRaises(PIVError):
            Request.decode(bytes.fromhex("A3037E0000000000"))

    def test_pd_passes_opaque_identifier_without_tag_validation(self):
        for identifier in (b"\x00", b"\xff", b"\x7f\x80", b"\x30\x01"):
            payload = b"\xa3" + bytes([len(identifier)]) + identifier + bytes(5)
            self.assertEqual(Request.decode(payload).object_id, identifier)
            pd = Peripheral({identifier: bytes.fromhex("5300")})
            acu = Controller(payload)
            while not acu.done:
                acu.receive(pd.exchange(acu.command))
            self.assertEqual(acu.data, bytes.fromhex("5300"))
            self.assertIsNone(acu.error)

    def test_pd_compares_opaque_selector_without_tag_validation(self):
        for selector in (b"\x00", b"\xff", b"\x7f\x80", b"\x30\x01"):
            payload = b"\xa3\x01\x7e" + bytes([len(selector)]) + selector + bytes(4)
            self.assertEqual(Request.decode(payload).tag, selector)
            pd = Peripheral({b"\x7e": bytes.fromhex("53033001AA")})
            acu = Controller(payload)
            while not acu.done:
                acu.receive(pd.exchange(acu.command))
            self.assertEqual(acu.error, 0x1024)
            self.assertEqual(acu.data, b"")

    def test_fragment_boundaries_can_split_tlv_headers(self):
        for children, boundary in (
            (b"\x30\x6c" + bytes(108) + bytes.fromhex("5f2f024800"), b"\x5f\x2f"),
            (b"\x30\x6a" + bytes(106) + b"\x70\x82\x01\x00" + bytes(256), b"\x82\x01"),
        ):
            header = (b"\x53\x81" + bytes([len(children)]) if len(children) < 256
                      else b"\x53\x82" + len(children).to_bytes(2, "big"))
            data = header + children
            self.assertEqual(data[113:115], boundary)
            pd = Peripheral({b"\x7e": data})
            acu = Controller(Request(b"\x7e"))
            while not acu.done:
                acu.receive(pd.exchange(acu.command))
            self.assertEqual(acu.data, data)

    def test_independent_crc_examples(self):
        for literal in ("537F0D00046E00802500006E38", "53000900046100C066"):
            data = bytes.fromhex(literal)
            self.assertEqual(crc16(data[:-2]), int.from_bytes(data[-2:], "little"))

    def test_crc_length_address_and_sequence(self):
        good = frame(b"\x60", 1)
        for pos in range(len(good)):
            damaged = bytearray(good)
            damaged[pos] ^= 1
            with self.assertRaises(ValueError):
                decode_frame(damaged)
        pd = Peripheral()
        with self.assertRaises(ValueError):
            pd.exchange(frame(b"\x60", 1, address=2))
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 3)))[2], b"\x41\x04")

    def test_poll_fragment_duplicate_reject_abort(self):
        data = b"\x53\x82\x01\x00" + bytes(256)
        pd = Peripheral({b"\x7e": data})
        request = frame(Request(b"\x7e").encode(), 1)
        self.assertEqual(decode_frame(pd.exchange(request))[2], b"\x40")
        self.assertEqual(decode_frame(pd.exchange(frame(Request(b"\x7e").encode(), 2)))[2], b"\x41\x09")
        poll = frame(b"\x60", 3)
        first = pd.exchange(poll)
        self.assertEqual(len(first), 128)
        self.assertEqual(pd.exchange(poll), first)
        self.assertEqual(pd.position, 114)
        second = pd.exchange(frame(b"\x60", 1))
        self.assertEqual(decode_frame(second)[2][3:5], b"\x72\x00")
        self.assertEqual(decode_frame(pd.exchange(frame(b"\xa2", 2)))[2], b"\x40")
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 3)))[2], b"\x40")
        self.assertIsNone(pd.pending)

    def test_snapshot_and_empty_completion(self):
        objects = {b"\x7e": b"\x53\x00"}
        pd = Peripheral(objects)
        pd.exchange(frame(Request(b"\x7e", offset=2).encode(), 1))
        objects[b"\x7e"] = b"\x53\x01\xff"
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 2)))[2], b"\x80" + bytes(6))

    def test_terminal_errors(self):
        for code in (0x1024, 0x1026, 0x1023, 0x0002, 0x1021):
            pd = Peripheral(error=code)
            self.assertEqual(decode_frame(pd.exchange(frame(Request(b"\x7e").encode(), 1)))[2], b"\x40")
            self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 2)))[2], b"\x8a" + code.to_bytes(2, "little"))
            self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 3)))[2], b"\x40")

    def test_resource_limit(self):
        pd = Peripheral({b"\x7e": b"\x53\x00"}, resource_limit=1)
        pd.exchange(frame(Request(b"\x7e").encode(), 1))
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 2)))[2], b"\x8a\x21\x10")

    def test_sequence_zero_reprocesses_and_clears_pending(self):
        pd = Peripheral({b"\x7e": b"\x53\x00"})
        start = frame(Request(b"\x7e").encode(), 0)
        pd.exchange(start)
        pd.objects[b"\x7e"] = b"\x53\x01\xaa"
        pd.exchange(start)
        self.assertEqual(pd.pending, b"\x53\x01\xaa")
        pd.exchange(frame(b"\x60", 0))
        self.assertIsNone(pd.pending)

    def test_invalid_request_async_error(self):
        pd = Peripheral()
        self.assertEqual(decode_frame(pd.exchange(frame(b"\xa3\x00", 1)))[2], b"\x40")
        self.assertEqual(decode_frame(pd.exchange(frame(b"\x60", 2)))[2], b"\x8a\x05\x00")

    def test_controller_delay_error_and_status_word(self):
        pd = Peripheral(error=0x1023, delay_polls=4, status_word=0x6982)
        acu = Controller(Request(b"\x7e"))
        exchanges = 0
        while not acu.done:
            acu.receive(pd.exchange(acu.command))
            exchanges += 1
        self.assertEqual(exchanges, 6)
        self.assertEqual((acu.error, acu.status_word), (0x1023, 0x6982))

    def test_controller_reassembly_validation(self):
        for payload in ("80030001000100AA", "80030000000200AA", "80030000000400AABBCCDD"):
            acu = Controller(Request(b"\x7e"))
            acu.receive(frame(b"\x40", 1, True))
            with self.assertRaises(ValueError):
                acu.receive(frame(bytes.fromhex(payload), 2, True))
        acu = Controller(Request(b"\x7e"))
        acu.receive(frame(b"\x40", 1, True))
        reply = frame(bytes.fromhex("80030000000100AA"), 2, True)
        acu.receive(reply)
        acu.receive(reply)
        self.assertEqual(acu.data, b"\xaa")
        with self.assertRaises(ValueError):
            acu.receive(frame(bytes.fromhex("80040001000100BB"), 3, True))
        acu.receive(frame(bytes.fromhex("80030003000000"), 3, True))
        self.assertTrue(acu.done)
        self.assertEqual(acu.error, "multipart-terminated")
        self.assertEqual(acu.data, b"")

    def test_empty_success_and_first_reply_termination_are_distinct(self):
        for payload, error in (("80000000000000", None),
                               ("80030003000000", "multipart-terminated"),
                               ("80030004000000", "multipart-terminated")):
            acu = Controller(Request(b"\x7e"))
            acu.receive(frame(b"\x40", 1, True))
            acu.receive(frame(bytes.fromhex(payload), 2, True))
            self.assertTrue(acu.done)
            self.assertEqual(acu.error, error)
            self.assertEqual(acu.data, b"")

    def test_osdp30_rejects_old_five_byte_getdata_payload(self):
        pd = Peripheral()
        acu = Controller(bytes.fromhex("A35FC1023000"))
        while not acu.done:
            acu.receive(pd.exchange(acu.command))
        self.assertEqual(acu.error, 0x0005)

    def test_maximum_multipart_transfer(self):
        data = b"\x53\x82\xff\xfb" + bytes(65531)
        pd = Peripheral({b"\x7e": data})
        acu = Controller(Request(b"\x7e"))
        count = 0
        while not acu.done:
            acu.receive(pd.exchange(acu.command))
            count += 1
        self.assertEqual(acu.data, data)
        self.assertEqual(count, 1 + (65535 + 113) // 114)

    def test_independent_checker_rejects_corruption(self):
        manifest = (DIRECTORY / "manifest.json").read_text()
        for mutation in ("crc", "missing-completion", "oracle"):
            examples = json.loads((DIRECTORY / "examples.json").read_text())
            if mutation == "crc":
                row = examples["cases"][0]["exchanges"][1]
                row["reply_hex"] = row["reply_hex"][:-4] + "0000"
            elif mutation == "missing-completion":
                examples["cases"][0]["exchanges"].pop()
            else:
                examples["cases"][0]["expected_selected_hex"] = "00"
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "manifest.json").write_text(manifest)
                (directory / "examples.json").write_text(json.dumps(examples))
                with self.assertRaises(AssertionError, msg=mutation):
                    check(directory)

    def test_committed_examples(self):
        self.assertGreater(check(), 15)
        self.assertEqual(generate(), json.loads((DIRECTORY / "examples.json").read_text()))


if __name__ == "__main__":
    unittest.main()
