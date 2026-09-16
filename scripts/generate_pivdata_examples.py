#!/usr/bin/env python3
"""Regenerate transcripts from committed fixed input/output oracle fixtures."""

import json
from pathlib import Path

from pivdata_simulator import PIVError, Request, transcript

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "worked-examples" / "pivdata"


def generate():
    manifest = json.loads((DIRECTORY / "manifest.json").read_text())
    cases = []
    for fixture in manifest["cases"]:
        raw = bytes.fromhex(fixture["request_hex"])
        try:
            request = Request.decode(raw)
        except PIVError:
            request = raw
        case = dict(fixture)
        case["exchanges"] = transcript(request, bytes.fromhex(fixture["card_response_hex"]),
                                       fixture.get("injected_error"),
                                       fixture.get("delay_polls", 0),
                                       fixture.get("status_word"))
        cases.append(case)
    return {"schema": 1, "frame_limit": 128, "fragment_limit": 114,
            "secure_channel": False, "cases": cases}


if __name__ == "__main__":
    output = DIRECTORY / "examples.json"
    output.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"Generated {output.relative_to(ROOT)}")
