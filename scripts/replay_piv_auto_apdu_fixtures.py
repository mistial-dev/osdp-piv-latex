#!/usr/bin/env python3
"""Replay committed PIV Auto / SD 33 APDU transcript fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from piv_auto_apdu import parse_dynamic_auth_response, parse_general_authenticate_apdu, profile_by_alg_ref


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURE_DIRS = [
    REPO_ROOT / "test-vectors" / "nist-sd33-apdu",
    REPO_ROOT / "test-vectors" / "piv-auto-apdu",
]


def hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex("".join(value.split()))


def walk_exchanges(value: Any) -> list[dict[str, Any]]:
    exchanges: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "command" in value and "response" in value:
            exchanges.append(value)
        for child in value.values():
            exchanges.extend(walk_exchanges(child))
    elif isinstance(value, list):
        for child in value:
            exchanges.extend(walk_exchanges(child))
    return exchanges


def replay_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    exchanges = walk_exchanges(data)
    ga_exchanges = []
    errors = []
    for exchange in exchanges:
        command_hex = exchange.get("plain_command") or exchange.get("command")
        response_hex = exchange.get("plain_response") or exchange.get("response")
        if not isinstance(command_hex, str) or "87" not in command_hex[:8]:
            continue
        try:
            command = hex_to_bytes(command_hex)
            parsed = parse_general_authenticate_apdu(command)
            if parsed["key_ref"] not in {0x9A, 0x9C, 0x9D, 0x9E, 0x04}:
                continue
            response = hex_to_bytes(response_hex)
            if parsed["key_ref"] != 0x04:
                parse_dynamic_auth_response(response)
            profile = profile_by_alg_ref(parsed["algorithm_id"], parsed["key_ref"])
            ga_exchanges.append(
                {
                    "description": exchange.get("description", ""),
                    "algorithm_id": f"0x{parsed['algorithm_id']:02X}",
                    "key_ref": f"0x{parsed['key_ref']:02X}",
                    "profile": profile.profile_id if profile else None,
                    "input_len": len(parsed["input"]),
                    "response_len": len(response),
                }
            )
        except Exception as exc:  # noqa: BLE001 - diagnostics for transcript replay
            errors.append({"description": exchange.get("description", ""), "error": repr(exc)})
    return {
        "source": str(path.relative_to(REPO_ROOT)),
        "general_authenticate_count": len(ga_exchanges),
        "general_authenticate": ga_exchanges,
        "errors": errors,
    }


def fixture_files(paths: list[Path]) -> list[Path]:
    files = []
    for path in paths:
        if path.is_file() and path.suffix == ".json":
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, default=DEFAULT_FIXTURE_DIRS)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    files = fixture_files(args.paths)
    report = {
        "summary": {"status": "running", "files": len(files)},
        "files": [replay_file(path) for path in files],
    }
    errors = [error for file_report in report["files"] for error in file_report["errors"]]
    ga_count = sum(file_report["general_authenticate_count"] for file_report in report["files"])
    report["summary"].update(
        {
            "status": "passed" if not errors and ga_count else "failed",
            "general_authenticate_count": ga_count,
            "error_count": len(errors),
        }
    )
    text = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report["summary"]["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
