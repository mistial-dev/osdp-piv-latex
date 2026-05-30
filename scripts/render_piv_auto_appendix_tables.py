#!/usr/bin/env python3
"""Render Appendix C worked PIV Auto example tables from verified JSON output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from piv_auto_apdu import parse_general_authenticate_apdu


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT = REPO_ROOT / "test-vectors" / "piv-auto-demo" / "generated" / "piv-auto-simulation-report.json"
DEFAULT_OUTPUT = REPO_ROOT / "tables" / "piv-auto-worked-examples.tex"


def latex_escape(value: object) -> str:
    text = str(value)
    return (
        text.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("$", r"\$")
        .replace("#", r"\#")
        .replace("_", r"\_")
        .replace("{", r"\{")
        .replace("}", r"\}")
    )


def hex_cell(value: str) -> str:
    return rf"\HexBytes{{{value}}}"


def hex_part(macro: str, value: bytes) -> str:
    if not value:
        return ""
    return rf"\{macro}{{{value.hex().upper()}}}"


def read_tlv_parts(data: bytes, offset: int = 0) -> tuple[bytes, bytes, bytes, bytes, int]:
    tag_start = offset
    if offset >= len(data):
        raise ValueError("missing tag")
    offset += 1
    if data[tag_start] & 0x1F == 0x1F:
        while True:
            if offset >= len(data):
                raise ValueError("truncated high-tag-number tag")
            more = data[offset] & 0x80
            offset += 1
            if not more:
                break
    length_start = offset
    if offset >= len(data):
        raise ValueError("missing length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0:
            raise ValueError("indefinite length is not supported")
        if offset + count > len(data):
            raise ValueError("truncated length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    value_start = offset
    end = value_start + length
    if end > len(data):
        raise ValueError("truncated value")
    return data[tag_start:length_start], data[length_start:value_start], data[value_start:end], data[tag_start:end], end


def segmented_challenge(value: str) -> str:
    return hex_part("ApduChallenge", bytes.fromhex(value))


def segmented_general_authenticate_apdu(value: str) -> str:
    apdu = bytes.fromhex(value)
    if len(apdu) < 5:
        raise ValueError("truncated APDU")
    lc1 = apdu[4]
    if lc1 == 0:
        if len(apdu) < 7:
            raise ValueError("truncated extended APDU")
        lc = int.from_bytes(apdu[5:7], "big")
        length_part = apdu[4:7]
        offset = 7
    else:
        lc = lc1
        length_part = apdu[4:5]
        offset = 5
    data = apdu[offset : offset + lc]
    le = apdu[offset + lc :]
    outer_tag, outer_len, outer_value, _outer_tlv, end = read_tlv_parts(data)
    if outer_tag != b"\x7C" or end != len(data):
        raise ValueError("GENERAL AUTHENTICATE data must be one 7C template")

    response_tag, response_len, response_value, _response_tlv, child_offset = read_tlv_parts(outer_value)
    challenge_tag, challenge_len, challenge_value, _challenge_tlv, child_end = read_tlv_parts(outer_value, child_offset)
    if response_tag != b"\x82" or response_value != b"" or challenge_tag != b"\x81" or child_end != len(outer_value):
        raise ValueError("GENERAL AUTHENTICATE template must contain empty 82 and 81 challenge")

    return "".join(
        [
            hex_part("ApduHeader", apdu[:4]),
            hex_part("ApduLength", length_part),
            hex_part("ApduTemplate", outer_tag + outer_len),
            hex_part("ApduResponse", response_tag + response_len),
            hex_part("ApduTemplate", challenge_tag + challenge_len),
            hex_part("ApduChallenge", challenge_value),
            hex_part("ApduLength", le),
        ]
    )


def segmented_dynamic_auth_response(value: str) -> str:
    response = bytes.fromhex(value)
    status = b""
    body = response
    if len(response) >= 2:
        status = response[-2:]
        body = response[:-2]
    outer_tag, outer_len, outer_value, _outer_tlv, end = read_tlv_parts(body)
    if outer_tag != b"\x7C" or end != len(body):
        raise ValueError("response must be one 7C template")
    response_tag, response_len, response_value, _response_tlv, child_end = read_tlv_parts(outer_value)
    if response_tag != b"\x82" or child_end != len(outer_value):
        raise ValueError("Dynamic Authentication Template response must contain one 82 field")
    return "".join(
        [
            hex_part("ApduTemplate", outer_tag + outer_len),
            hex_part("ApduResponse", response_tag + response_len),
            hex_part("ApduResponse", response_value),
            hex_part("ApduStatus", status),
        ]
    )


def code_cell(value: object) -> str:
    return rf"\code{{{latex_escape(value)}}}"


def hex_byte_with_prefix(value: object) -> str:
    text = str(value)
    if text.lower().startswith("0x"):
        return rf"\code{{0x}}\ApduHeader{{{text[2:].upper()}}}"
    return hex_part("ApduHeader", bytes.fromhex(text))


def profile_source(item: dict[str, object]) -> str:
    note = item.get("profile_note")
    source = latex_escape(item["source"])
    if note:
        return f"{source} {latex_escape(note)}."
    return source


def profile_sort_key(item: dict[str, object]) -> tuple[int, str]:
    profile = str(item["profile"])
    key_type_order = {"rsa1024": 0, "rsa2048": 1, "rsa3072": 2, "ecp256": 3, "ecp384": 4}
    key_type = profile.split("-", 1)[1]
    slot = profile.split("-", 1)[0]
    return key_type_order.get(key_type, 99), slot


def render_profile_table(item: dict[str, object]) -> str:
    profile = str(item["profile"])
    title = f"PIV Auto Worked Example: {item['label']}"
    parsed_command = parse_general_authenticate_apdu(bytes.fromhex(str(item["general_authenticate_command_hex"])))
    fields = [
        ("Profile", code_cell(profile)),
        ("Source", profile_source(item)),
        ("Algorithm ID", hex_byte_with_prefix(item["algorithm_id"])),
        ("Key Reference", hex_byte_with_prefix(item["key_ref"])),
        ("KMAC Challenge Digest", segmented_challenge(str(item["challenge_digest_hex"]))),
        ("Tag 81 Challenge Input", hex_part("ApduChallenge", parsed_command["input"])),
        ("GENERAL AUTHENTICATE APDU", segmented_general_authenticate_apdu(str(item["general_authenticate_command_hex"]))),
        ("Dynamic Authentication Response", segmented_dynamic_auth_response(str(item["dynamic_auth_response_hex"]))),
        ("Response Tag 82 Length", f"{item['response_82_length']} bytes"),
    ]
    lines = [
        rf"\begin{{SimpleTable}}{{{latex_escape(title)}}}{{2}}",
        r"  {|L{0.24\SimpleUsableWidth}|K{0.76\SimpleUsableWidth}|}",
        r"  {\TableHeaderCell{Field} & \TableHeaderCell{Value}}",
    ]
    lines.extend(f"  {latex_escape(name)} & {value} \\\\\\hline" for name, value in fields)
    lines.append(r"\end{SimpleTable}")
    return "\n".join(lines)


def render(report_path: Path = DEFAULT_REPORT) -> str:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    coverage = sorted(report["profile_coverage"], key=profile_sort_key)
    lines = [
        "% Generated by scripts/render_piv_auto_appendix_tables.py; do not hand edit.",
        rf"\TableNote{{Worked examples are generated from \code{{{report_path.relative_to(REPO_ROOT)}}}.}}",
        "",
    ]
    for item in coverage:
        lines.append(render_profile_table(item))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail if output differs from generated content")
    args = parser.parse_args()

    text = render(args.report)
    if args.check:
        existing = args.output.read_text(encoding="utf-8")
        if existing != text:
            raise SystemExit(f"{args.output} is stale; rerun scripts/render_piv_auto_appendix_tables.py")
        return 0
    args.output.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
