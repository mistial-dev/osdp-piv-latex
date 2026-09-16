#!/usr/bin/env python3
"""Render checked packet examples into the proposal's SM/VCI appendix."""
import argparse
import json
from pathlib import Path

from check_sm_vci_examples import verify_examples

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "tables/sm-vci-worked-examples.tex"
NAMES = {0x40: "ACK", 0x60: "POLL", 0x85: "CARDSTATUSR", 0x86: "PIVSPER",
         0x89: "PIVSTATUS", 0xA9: "CARDSTATUS", 0xAA: "PIVSPE", 0xAD: "PIVXMITPAIRING"}
CASES = {
    "contact-sm": ("Credential SM over contact",
        "The PD prepares a contact credential and reports SM established without VCI. "
        "The reply identifies the CVC issuer and trust anchor used for that SM session."),
    "cache-before-card": ("PIN before credential presentation",
        "The PD collects the PIN locally and reports completion before the credential is presented. "
        "Initial selection and SM establishment preserve the cache. The ACU then completes "
        "pairing and requests PIN verification over VCI."),
    "auto-pairing-required": ("PIV Auto needs commanded pairing",
        "In this modeled case, the configured PIV Auto authentication requires VCI. SM is established, "
        "but pairing remains necessary. PIV Auto reports the unmet condition and ends the attempt. "
        "A later poll receives ACK; the ACU can begin commanded pairing."),
    "diagnostic-cvc-hash": ("SM failure diagnostics",
        "In this modeled case, PIV Auto reports Result 0x02, Detail 0x04: invalid authentication cryptogram. "
        "The ACU then requests the SM diagnostic "
        "record. The PD returns the failure reason and the hash of the received CVC, with no "
        "further credential commands. Three fragments carry the 35-byte record. The CVC bytes "
        "used for the hash come from the existing capture."),
    "pin-expiration-idle": ("PIN cache expires while idle",
        "The PD acquires a PIN at t=0 with a ten-second validity period. At t=10 the PD "
        "erases the PIN. A poll receives ACK because no operation is pending. A status query "
        "reports an empty cache; a subsequent verification request ends with no cached PIN. "
        "The PD sends no VERIFY. This example models the timing and credential state."),
    "pin-expiration-waiting": ("Expiration while waiting for a credential",
        "The ACU arms cached-PIN verification with Auto Execute flag 0x02. "
        "The credential is absent when the cache expires at t=10. The PD ends the pending "
        "request with PIVSPER 0x0A (no cached PIN). This example models the waiting state."),
    "pin-expiration-boundary": ("Expiration before VERIFY submission",
        "The PD accepts verification at t=9. Before the PD submits VERIFY, the deadline "
        "is reached at t=10. The PD returns PIVSPER 0x0A (no cached PIN) and sends no VERIFY. "
        "Acceptance alone does not reserve the PIN beyond its deadline. Timing is modeled."),
    "pin-expiration-submitted": ("Expiration after VERIFY submission",
        "The PD submits VERIFY at t=9, before the deadline. The cache expires at t=10 "
        "while the exchange is completing. The PD reports successful verification, then "
        "reports an empty cache with the credential still PIN verified. Credential APDUs "
        "come from the contactless capture; the timing is modeled."),
    "pin-expiration-reuse": ("PIN reuse preserves the original deadline",
        "Two explicit contact verification requests use the same cached PIN at t=1 and t=2. "
        "Both succeed. At t=10, the cache expires and the credential remains PIN verified. "
        "The successes and timing are modeled; the example demonstrates the PD state rules."),
    "auto-status-word": ("Credential failure status across two fragments",
        "PIV Auto reports a modeled GENERAL AUTHENTICATE rejection: Result 0x06, Detail 0x00. "
        "The credential status is 0x6982 (security status not satisfied). The first fragment "
        "ends with SW1, 0x69; the second carries SW2, 0x82. The ACU reassembles the complete "
        "record before interpreting the status word."),
    "sm-credential-rejection": ("Incorrect PIN preserves SM and VCI",
        "This modeled case starts with SM, VCI, and a cached PIN available. The credential "
        "returns an authenticated 0x63C2 (incorrect PIN, two attempts remain). The PD reports "
        "PIN mismatch and clears the cache and PIN-verification state. SM and VCI remain "
        "established. The SPE reply carries the mismatch result; a separate Mode 0x06 query "
        "retrieves remaining attempts. The ACU can acquire a corrected PIN and request "
        "verification again using the existing session.")}


def escape(text):
    return text.replace("&", r"\&").replace("_", r"\_").replace("%", r"\%")


def dump(raw):
    words = raw.hex(" ").upper().split()
    return r"\newline ".join(r"\texttt{" + " ".join(words[i:i + 12]) + "}"
                              for i in range(0, len(words), 12))


def note(raw, fallback):
    payload = raw[5:-2]
    if payload[0] == 0x40:
        return "Accepted, or no completion pending."
    if payload[0] == 0x85:
        if payload[1] == 2:
            total, offset, size = (int.from_bytes(payload[i:i + 2], "little") for i in (2, 4, 6))
            return f"Diagnostic: total 0x{total:04X}, offset 0x{offset:04X}, fragment 0x{size:04X}."
        if payload[1] != 1:
            raise ValueError("unknown CARDSTATUSR type")
        state = {0: "SM absent", 1: "SM and VCI established", 2: "SM established without VCI"}[payload[3]]
        return "Status " + f"0x{payload[3]:02X}" + ": " + state + "."
    if payload[0] == 0x86:
        return {0: "Result 0x00: requested PIN operation completed.",
                3: "Result 0x03: PIN mismatch.",
                10: "Result 0x0A: no cached PIN."}.get(payload[1], fallback)
    if payload[0] == 0x89:
        result, detail = payload[7:9]
        meanings = {(5, 1): "pairing code required", (2, 4): "invalid authentication cryptogram"}
        return f"Result 0x{result:02X}, Detail 0x{detail:02X}: {meanings[(result, detail)]}."
    return fallback


def render(document):
    verify_examples(document)
    out = ["% Generated by scripts/render_sm_vci_examples.py; do not hand edit."]
    for example in document["examples"]:
        if example["id"] not in CASES:
            continue
        title, intro = CASES[example["id"]]
        out += [r"\Needspace{24\baselineskip}", r"\subsection{" + title + "}",
                r"\label{ex:sm-" + example["id"] + "}", intro, "",
                r"Example ID: \texttt{" + example["id"] + "}."]
        if example["id"] == "pin-expiration-idle":
            out += [r"\label{ex:pin-expiration}"]
        if example["id"] == "auto-status-word":
            out += [r"\input{figures/auto-status-word}"]
        if example.get("source") and not example["id"].startswith(("diagnostic-", "pin-expiration-")):
            out.append("Credential exchanges come from the " + ("contact" if example["id"] == "contact-sm" else "contactless")
                       + " card01 capture. The complete replay retains its original APDU order.")
        if example["id"] == "contact-sm":
            payload = bytes.fromhex(example["exchanges"][-1]["reply"])[5:-2]
            out += [r"\begin{SimpleTable}{Reported security state}{3}",
                    r"{|L{0.30\SimpleUsableWidth}|L{0.32\SimpleUsableWidth}|L{0.38\SimpleUsableWidth}|}",
                    r"{\TableHeaderCell{Field} & \TableHeaderCell{Value} & \TableHeaderCell{Notes}}"]
            for field, value, explanation in (
                ("Status Type", payload[1:2], "Standard credential status."),
                ("Credential Security Status", payload[3:4], "SM established without VCI."),
                ("SM Trust Anchor ID", payload[4:5], "Loaded anchor used to validate SM."),
                ("SM CVC IIN", payload[5:13], "Issuer named by the credential's SM CVC."),
                ("SM Anchor IIN", payload[13:21], "Same issuer: direct trust path.")):
                out.append(field + r" & \code{0x" + value.hex().upper() + "} & " + explanation + r" \\\hline")
            out += [r"\end{SimpleTable}"]
        out += [r"\begingroup\small",
                r"\begin{SimpleTable}{OSDP command and reply exchange}{3}",
                r"{|L{0.20\SimpleUsableWidth}|L{0.50\SimpleUsableWidth}|L{0.30\SimpleUsableWidth}|}",
                r"{\TableHeaderCell{Message} & \TableHeaderCell{Packet bytes (hex)} & \TableHeaderCell{Notes}}"]
        exchanges = example["exchanges"][1:] if example["id"].startswith("diagnostic-") else example["exchanges"]
        for exchange in exchanges:
            for key, actor in (("request", "ACU"), ("reply", "PD")):
                raw = bytes.fromhex(exchange[key])
                description = (note(raw, exchange["notes"])
                               if key == "reply" and example["id"] != "auto-status-word" else exchange["notes"])
                request = bytes.fromhex(exchange["request"])
                if key == "reply" and request[5:7] == bytes.fromhex("AA00"):
                    description = {0: "Cache empty; credential PIN verification absent.",
                                   1: "Cached PIN available; credential PIN verification absent.",
                                   2: "Cache empty; credential PIN verified.",
                                   3: "Cached PIN available; credential PIN verified."}[raw[6]]
                if key == "reply" and raw[5] == 0x40:
                    request = bytes.fromhex(exchange["request"])
                    description = "No completion pending." if request[5] == 0x60 else "Command accepted."
                if raw[5] == 0x60 and key == "request":
                    description = "Poll for completion."
                if example["id"].startswith("pin-expiration-"):
                    description = f"t={exchange['time_seconds']} s. " + description
                out.append(actor + r"\newline \texttt{" + NAMES[raw[5]] + "} & "
                           + dump(raw) + " & " + escape(description) + r" \\\hline")
        out += [r"\end{SimpleTable}", r"\endgroup", ""]
    return "\n".join(out) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = render(json.loads((ROOT / "worked-examples/sm-vci/examples.json").read_text()))
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit("SM/VCI example tables need regeneration")
    else:
        OUTPUT.write_text(result)


if __name__ == "__main__":
    main()
