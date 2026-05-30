#!/usr/bin/env python3
"""Import local NIST SD 33 APDU transcript JSON into repository fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO_ROOT.parent / "nist_sd_33_vectors"
DEFAULT_OUTPUT = REPO_ROOT / "test-vectors" / "nist-sd33-apdu"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_vectors(source: Path, output: Path) -> dict[str, object]:
    if not source.exists():
        raise FileNotFoundError(f"{source} does not exist")
    output.mkdir(parents=True, exist_ok=True)
    copied = []
    for path in sorted(source.glob("nist_special_database_33_card_*.json")):
        dest = output / path.name
        shutil.copyfile(path, dest)
        copied.append({"path": str(dest.relative_to(REPO_ROOT)), "source_sha256": sha256_file(path)})
    notes = source / "NOTES.md"
    if notes.exists():
        warning = (
            "These byte-complete files are committed public test fixtures from public test\n"
            "cards. They may include plaintext PINs, pairing codes, OPACITY ephemeral\n"
            "private keys, shared secrets, and derived session keys captured for replay and\n"
            "validation. Do not use any value in these files as operational secret material.\n\n"
        )
        (output / "NOTES.md").write_text(warning + notes.read_text(encoding="utf-8"), encoding="utf-8")
    manifest = {
        "source": {
            "name": "NIST Special Database 33 / NIST IR 8347 PIV test-card APDU captures",
            "import_note": "Imported from a local sibling checkout; this path is intentionally not required by the document.",
            "public_reference": "https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8347.pdf",
        },
        "imported_files": copied,
        "notes": (
            "Fixtures are byte-complete public test-card APDU transcripts for NIST test cards with VCI support. "
            "They may include PINs, pairing codes, ephemeral private keys, shared secrets, and derived session keys; "
            "do not use them as operational secret material."
        ),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest = import_vectors(args.source, args.output)
    print(json.dumps({"summary": {"status": "imported", "count": len(manifest["imported_files"])}, **manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
