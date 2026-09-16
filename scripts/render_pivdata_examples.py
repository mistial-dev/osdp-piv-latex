#!/usr/bin/env python3
"""Render the PIVGETDATA appendix from independently checked JSON exchanges."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from check_pivdata_examples import check


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "worked-examples" / "pivdata"
OUTPUT = ROOT / "tables" / "pivdata-worked-examples.tex"
REPOSITORY = "https://github.com/mistial-dev/osdp-piv-latex/blob/master/"
ERROR_MEANINGS = {
    0x0001: "smart-card error",
    0x0002: "smart-card timeout",
    0x0004: "required TLV missing",
    0x0005: "invalid parameter",
    0x0006: "secure channel required",
    0x0007: "invalid multi-part transfer",
    0x0008: "multi-part fragment out of sequence",
    0x0009: "multi-part fragment out of bounds",
    0x1020: "function not supported by credential",
    0x1021: "insufficient PD memory or storage",
    0x1022: "insufficient credential memory or storage",
    0x1023: "credential security status not satisfied",
    0x1024: "data object or tag not found",
    0x1025: "VCI not established",
    0x1027: "credential not present or removed",
    0x1029: "ambiguous element selection",
    0x102A: "malformed credential-object encoding",
    0x102B: "transfer length exceeded",
}
REPRESENTATIVE_CASES = (
    "discovery-whole", "discovery-pin-policy", "chuid-fascn", "chuid-fascn-value",
    "chuid-guid", "chuid-guid-value", "chuid-prefix", "certificate-whole", "certificate-element",
    "certificate-compressed-element", "certificate-offset256", "key-history",
    "bit-empty", "empty-5300", "empty-success", "zero-length-child",
    "missing-child", "empty-missing-child", "duplicate-child",
)
TITLES = {
    "discovery-whole": "Complete Discovery Object",
    "discovery-pin-policy": "Discovery PIN Usage Policy (0x5F2F)",
    "chuid-fascn": "Read the FASC-N element (0x30)",
    "chuid-fascn-value": "Read the FASC-N value",
    "chuid-guid": "Read the UUID element (0x34)",
    "chuid-guid-value": "Read the UUID value",
    "chuid-prefix": "Bounded CHUID prefix",
    "certificate-whole": "Complete certificate object",
    "certificate-element": "Read the certificate element (0x70)",
    "certificate-compressed-element": "Read a compressed certificate element",
    "certificate-offset256": "Read a range within the certificate element",
    "key-history": "Complete Key History object",
    "bit-empty": "BIT Group with no biometric templates",
    "empty-5300": "Empty 0x53 container",
    "empty-success": "Zero-byte successful response",
    "zero-length-child": "Existing child with an empty value",
    "missing-child": "Missing direct child",
    "empty-missing-child": "Element request against an empty response",
    "duplicate-child": "Ambiguous direct-child selection",
}

PURPOSES = {
    "discovery-whole": "Read the complete Discovery Object. Tag Length 0x00 keeps its outer tag 0x7E and its length, followed by all its contents.",
    "discovery-pin-policy": "Read the PIN Usage Policy from the Discovery Object. The reply contains tag 0x5F2F, length 0x02, and the two policy bytes.",
    "chuid-fascn": "Read the FASC-N element from the CHUID without depending on its position. The returned element begins with tag 0x30 and length 0x19, followed by the FASC-N.",
    "chuid-fascn-value": "Read just the FASC-N bytes. Offset 0x0002 skips the selected element's 0x30 0x19 header; Requested Length 0x0019 limits the result to the FASC-N value.",
    "chuid-guid": "Read the UUID (also called the GUID) element from the CHUID. The returned element begins with tag 0x34 and length 0x10, followed by the UUID.",
    "chuid-guid-value": "Read just the UUID bytes. Offset 0x0002 skips the selected element's 0x34 0x10 header; Requested Length 0x0010 limits the result to the UUID value.",
    "chuid-prefix": "Read the first 0x0010 bytes of the CHUID, starting with its outer tag and length. In this capture, the range ends partway through the FASC-N element.",
    "certificate-whole": "Read the complete certificate object, including its outer 0x53 header and all elements inside it. The result is larger than one reply, so the ACU polls for the remaining fragments.",
    "certificate-element": "Read element 0x70, including its tag, encoded length, and certificate bytes. This omits the enclosing 0x53 header and the other elements in the object. The 0x70 header appears once in the returned data.",
    "certificate-compressed-element": "Read element 0x70 from a card that stores a compressed certificate. The PD returns the original tag, length, and compressed bytes. The ACU can read the object's certificate-information element to determine how to interpret the value.",
    "bit-empty": "Read a Biometric Information Template (BIT) Group with no biometric templates. The reply keeps the outer 0x7F61 tag and the element that reports a count of zero.",
    "key-history": "Read the complete Key History object. Its outer 0x53 header and all elements inside it are returned unchanged.",
    "empty-5300": "Read an object with no contents. The reply still contains two bytes, 0x53 0x00, because whole-object selection includes the outer tag and length.",
    "certificate-offset256": "Read 0x0104 bytes starting at offset 0x0100 of the certificate element, counting from tag 0x70. The reply offsets are 0x0000, 0x0072, and 0x00E4; each identifies a position within the 0x0104 returned bytes.",
    "empty-success": "Handle a successful card response with zero data bytes. The PD sends one PIVGETDATAR with all three multi-part fields zero.",
    "zero-length-child": "Read an element whose value is empty. The reply contains its tag and zero length, 0x30 0x00, for a total of two bytes.",
    "missing-child": "Request an element that is absent from the object. The PD accepts the command, then reports PIVERROR on the next poll.",
    "empty-missing-child": "Request an element when the card returns no data. The PD reports that the tag was not found. A whole-object request for the same response would succeed with zero bytes.",
    "duplicate-child": "Request a tag that occurs twice directly inside the outer container. Element selection requires a unique match, so the PD reports an error.",
}


def escape(value: object) -> str:
    replacements = {
        "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
        "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
        "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in str(value))


def code(value: object) -> str:
    return r"\texttt{" + escape(value) + "}"


def hex_bytes(data: bytes) -> str:
    return " ".join(f"0x{byte:02X}" for byte in data)


def frame_lines(encoded: str) -> list[str]:
    data = bytes.fromhex(encoded)
    def lines(part):
        return [part[pos:pos + 12].hex(" ").upper() for pos in range(0, len(part), 12)]
    if len(data) <= 100:
        return lines(data)
    return [*lines(data[:24]), f"... 0x{len(data) - 40:02X} bytes omitted ...", *lines(data[-16:])]


def request_table(encoded: str) -> str:
    data = bytes.fromhex(encoded)
    identifier_length = data[1]
    end = 2 + identifier_length
    tag_length = data[end]
    tag = data[end + 1:end + 1 + tag_length]
    offset = int.from_bytes(data[-4:-2], "little")
    requested = int.from_bytes(data[-2:], "little")
    rows = [
        ("Command", code("0xA3"), code("osdp_PIVGETDATA")),
        ("Identifier Length", code(f"0x{identifier_length:02X}"), "Bytes in Object Identifier."),
        ("Object Identifier", code("0x" + data[2:end].hex().upper()), "Object to read."),
        ("Tag Length", code(f"0x{tag_length:02X}"), "Bytes in Element Tag." if tag else "Select the whole object."),
        ("Element Tag", code("0x" + tag.hex().upper()) if tag else "Omitted", "Element to select." if tag else "Tag Length is zero."),
        ("Offset", code(f"0x{offset:04X}"), "Start at the selected tag." if offset == 0 else "Bytes to skip from the selected tag."),
        ("Requested Length", code(f"0x{requested:04X}"), "All remaining bytes." if requested == 0 else "Maximum bytes to return."),
    ]
    return "\n".join([
        r"\begin{SimpleTable}{Request fields}{3}",
        r"  {|L{0.30\SimpleUsableWidth}|L{0.27\SimpleUsableWidth}|L{0.43\SimpleUsableWidth}|}",
        r"  {\TableHeaderCell{Field} & \TableHeaderCell{Value} & \TableHeaderCell{Notes}}",
        *(field + " & " + value + " & " + notes + r" \\\hline" for field, value, notes in rows),
        r"\end{SimpleTable}",
    ])


def reply_notes(encoded: str) -> tuple[str, str]:
    payload = bytes.fromhex(encoded)[5:-2]
    if payload[0] == 0x80:
        total = int.from_bytes(payload[1:3], "little")
        offset = int.from_bytes(payload[3:5], "little")
        size = int.from_bytes(payload[5:7], "little")
        return "PIVGETDATAR", r"\newline ".join([
            f"Total {code(f'0x{total:04X}')}",
            f"Offset {code(f'0x{offset:04X}')}",
            f"Fragment {code(f'0x{size:04X}')}",
        ])
    if payload[0] == 0x8A:
        error = int.from_bytes(payload[1:3], "little")
        description = code(f"0x{error:04X}") + " (" + escape(ERROR_MEANINGS[error]) + ")"
        if len(payload) == 5:
            description += r"\newline SW1/SW2: " + code(hex_bytes(payload[3:]))
        return "PIVERROR", description
    if payload == b"\x40":
        return "ACK", "Acknowledgment."
    raise ValueError("unexpected reply in checked transcript")


def exchange_table(case: dict) -> str:
    exchanges = case["exchanges"]
    shown = list(range(len(exchanges))) if len(exchanges) <= 4 else [0, 1, len(exchanges) - 1]
    rows = []
    previous = -1
    for index in shown:
        if index > previous + 1:
            count = index - previous - 1
            rows.append("POLL/reply & Omitted & " + code(f"0x{count:02X}")
                        + r" exchanges; complete frames are in the JSON file. \\\hline")
        exchange = exchanges[index]
        command = "PIVGETDATA" if index == 0 else "POLL"
        note = "Read request." if index == 0 else "Poll " + code(f"0x{index:02X}") + "."
        reply, reply_note = reply_notes(exchange["reply_hex"])
        if reply == "ACK":
            reply_note = "Command accepted." if index == 0 else "Processing."
        for sender, message, encoded, notes in (
            ("ACU", command, exchange["command_hex"], note),
            ("PD", reply, exchange["reply_hex"], reply_note),
        ):
            packet = r"\newline ".join(code(line) for line in frame_lines(encoded))
            rows.append(sender + r"\newline " + code(message) + " & " + packet
                        + " & " + notes + (r" \\*\hline" if sender == "ACU" else r" \\\hline"))
        previous = index
    return "\n".join([
        r"\begingroup\small",
        r"\begin{SimpleTable}{Command and reply exchange}{3}",
        r"{|L{0.20\SimpleUsableWidth}|L{0.50\SimpleUsableWidth}|L{0.30\SimpleUsableWidth}|}",
        r"{\TableHeaderCell{Message} & \TableHeaderCell{Packet bytes (hex)} & \TableHeaderCell{Notes}}",
        *rows, r"\end{SimpleTable}", r"\endgroup",
    ])


def purpose(case: dict) -> str:
    notes = case.get("notes")
    if isinstance(notes, list):
        notes = " ".join(str(note) for note in notes)
    return str(notes or PURPOSES.get(case["name"], case["name"].replace("-", " ").capitalize() + "."))


def render_case(case: dict, sources: dict[str, dict]) -> str:
    name = case["name"]
    if not re.fullmatch(r"[a-z0-9-]+", name):
        raise ValueError(f"example ID is not label-safe: {name!r}")
    title = case.get("title", TITLES.get(name, name.replace("-", " ").capitalize()))
    lines = [r"\Needspace{28\baselineskip}",
             rf"\subsection{{{escape(title)}}}\label{{ex:pivdata-{name}}}",
             escape(purpose(case)), "", "Example ID: " + code(name) + "."]
    provenance = case["provenance"]
    if provenance["kind"] == "captured":
        source = provenance["source"]
        source_id = sources[source]["id"]
        lines.append(r"Source: \hyperref[pivdata-source-" + source_id + "]{" + escape(source_id) + "}.")
    else:
        lines.append("Source: constructed example.")
    lines += ["", request_table(case["request_hex"]), ""]
    if "expected_error" in case:
        lines.append("Result: " + code(f"osdp_PIVERROR 0x{case['expected_error']:04X}")
                     + " (" + escape(ERROR_MEANINGS[case["expected_error"]]) + ")"
                     + r"; see Section~\ref{sec:piverror}.")
    else:
        selected = bytes.fromhex(case["expected_selected_hex"])
        fragments = sum(bytes.fromhex(row["reply_hex"])[5] == 0x80 for row in case["exchanges"])
        lines.append(f"Result: {code(f'0x{len(selected):04X}')} returned bytes in {code(f'0x{fragments:02X}')} "
                     + ("data reply." if fragments == 1 else "data replies."))
    lines += ["", exchange_table(case), ""]
    return "\n".join(lines)


def render(directory: Path = DIRECTORY) -> str:
    # The checker compares fixed oracles and source hashes; the renderer never simulates frames.
    check(directory)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    examples = json.loads((directory / "examples.json").read_text(encoding="utf-8"))
    sources = {source["path"]: dict(source, id=f"S{index}")
               for index, source in enumerate(manifest["sources"], 1)}
    lines = ["% Generated by scripts/render_pivdata_examples.py; do not hand edit.",
             "All exchanges use PD address 0x01 and CRC-16. Each request table gives the field values; "
             "the packet bytes below it show how those values are encoded.",
             "", r"\href{run:worked-examples/pivdata/examples.json}{Complete machine-readable exchanges} "
             "include every frame. " + r"\href{run:worked-examples/pivdata/manifest.json}{The fixture manifest} "
             "records the inputs, expected results, source locations, and hashes. Hex includes the OSDP header and CRC, "
             "without an optional leading mark byte. Long replies show their first 0x18 and last 0x10 bytes; "
             "ellipsis text is not transmitted.", "", r"\subsection{Source fixtures}"]
    for path, source in sources.items():
        lines += [r"\phantomsection\label{pivdata-source-" + source["id"] + "}",
                  r"\noindent " + escape(source["id"]) + ": "
                  + r"\href{" + REPOSITORY + path + "}{"
                  + escape(Path(path).parent.name.replace("vci-vectors-", "NIST SD33 "))
                  + "}, contact card capture.", ""]
    cases = {case["name"]: case for case in examples["cases"]}
    lines += [f"The {len(REPRESENTATIVE_CASES)} examples below are a representative subset of "
              f"the {len(cases)} checked exchanges in the linked JSON file.", ""]
    for name in REPRESENTATIVE_CASES:
        lines.append(render_case(cases[name], sources))
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DIRECTORY)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--check", action="store_true", help="Fail if the generated appendix is stale")
    args = parser.parse_args()
    text = render(args.directory)
    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != text:
            raise SystemExit(f"{args.output} is stale; rerun scripts/render_pivdata_examples.py")
        print("Verified PIVGETDATA appendix matches checked transcripts")
    else:
        args.output.write_text(text, encoding="utf-8")
        print(f"Generated {args.output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
