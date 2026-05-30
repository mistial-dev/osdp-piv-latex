#!/usr/bin/env python3
"""Capture live PIV Auto GENERAL AUTHENTICATE APDUs from a PC/SC card."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from piv_auto_apdu import PROFILES, general_authenticate_apdu, parse_dynamic_auth_response, profile_input, select_piv_apdu, verify_pin_apdu


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "test-vectors" / "piv-auto-apdu" / "live-capture.json"


def select_reader(available, requested: str | None):
    if not available:
        raise SystemExit("No PC/SC readers found")
    if requested is None:
        return available[0]
    matching = [item for item in available if requested in str(item)]
    if not matching:
        names = "\n".join(f"  - {item}" for item in available)
        raise SystemExit(f"Requested PC/SC reader not found: {requested}\nAvailable readers:\n{names}")
    return matching[0]


def transmit(connection, apdu: bytes) -> tuple[bytes, int, int]:
    data, sw1, sw2 = connection.transmit(list(apdu))
    return bytes(data), sw1, sw2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--input-hex", required=True, help="Digest or RSA encoded-digest input, depending on --raw-input")
    parser.add_argument("--raw-input", action="store_true", help="Use --input-hex directly instead of profile encoding it")
    parser.add_argument("--pin", help="Optional PIN to VERIFY before GENERAL AUTHENTICATE")
    parser.add_argument("--reader", help="Substring of reader name to select")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    try:
        from smartcard.System import readers
    except ModuleNotFoundError as exc:
        raise SystemExit("Install pyscard to use live capture: python3 -m pip install pyscard") from exc

    available = readers()
    reader = select_reader(available, args.reader)
    connection = reader.createConnection()
    connection.connect()

    profile = PROFILES[args.profile]
    input_bytes = bytes.fromhex(args.input_hex)
    if not args.raw_input:
        input_bytes = profile_input(profile, input_bytes)

    exchanges = []
    for description, apdu in [("SELECT PIV", select_piv_apdu())]:
        data, sw1, sw2 = transmit(connection, apdu)
        exchanges.append({"description": description, "command": apdu.hex().upper(), "response": (data + bytes([sw1, sw2])).hex().upper()})
    if args.pin:
        apdu = verify_pin_apdu(args.pin)
        data, sw1, sw2 = transmit(connection, apdu)
        exchanges.append({"description": "VERIFY PIV PIN", "command": apdu.hex().upper(), "response": (data + bytes([sw1, sw2])).hex().upper()})
    apdu = general_authenticate_apdu(profile, input_bytes)
    data, sw1, sw2 = transmit(connection, apdu)
    response = data + bytes([sw1, sw2])
    parse_dynamic_auth_response(response)
    exchanges.append(
        {
            "description": f"GENERAL AUTHENTICATE ({profile.label})",
            "command": apdu.hex().upper(),
            "plain_command": apdu.hex().upper(),
            "response": response.hex().upper(),
            "plain_response": response[:-2].hex().upper() if response[-2:] == b"\x90\x00" else response.hex().upper(),
        }
    )

    report = {
        "description": "Live PIV Auto APDU capture",
        "metadata": {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "reader_name": str(reader),
            "profile": profile.profile_id,
            "algorithm_id": f"0x{profile.algorithm_id:02X}",
            "key_ref": f"0x{profile.key_ref:02X}",
        },
        "apdu_exchanges": exchanges,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": {"status": "captured", "out": str(args.out), "exchanges": len(exchanges)}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
