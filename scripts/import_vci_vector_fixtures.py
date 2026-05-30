#!/usr/bin/env python3
"""Import available NIST test-card VCI vector artifacts into fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from argparse import Namespace
from pathlib import Path
from typing import Any

from make_vci_trust_anchor import build_record
from validate_vci_chain import children, parse_cvc, parse_smcs, read_tlv, validate


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
DEFAULT_SD33_DIR = REPO_ROOT.parent / "nist_sd_33_vectors_v2"
DEFAULT_SM_VCI_DIR = REPO_ROOT.parent / "sm_vci_vectors"
DEFAULT_ANCHOR_OUTPUT = REPO_ROOT / "test-vectors" / "vci-trust-anchors"
DEFAULT_CVC_CORPUS_OUTPUT = REPO_ROOT / "test-vectors" / "vci-cvc-corpus"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def walk_dicts(value: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(value, dict):
        out.append(value)
        for child in value.values():
            out.extend(walk_dicts(child))
    elif isinstance(value, list):
        for child in value:
            out.extend(walk_dicts(child))
    return out


def find_smcs(data: dict[str, Any]) -> bytes:
    for item in walk_dicts(data):
        if item.get("data_object_tag") == "5FC122" and item.get("plain_response"):
            return bytes.fromhex(item["plain_response"])
    raise ValueError("source vector does not contain a 5FC122 plain_response")


def find_secure_cvc(data: dict[str, Any]) -> bytes:
    opacity = data.get("opacity", {})
    cvc_hex = opacity.get("cvc_raw") or opacity.get("cvc", {}).get("raw_hex")
    if cvc_hex:
        return bytes.fromhex(cvc_hex)

    candidates = []
    for item in walk_dicts(data):
        for key in ("plain_response", "general_authenticate_response", "response"):
            value = item.get(key)
            if isinstance(value, str) and value.startswith("7C") and "7F21" in value:
                candidates.append(bytes.fromhex(value))
    for candidate in candidates:
        tag, _length, value, _tlv, _end = read_tlv(candidate, 0)
        if tag != b"\x7c":
            continue
        for child_tag, _child_length, child_value, _child_tlv in children(value):
            if child_tag == b"\x82":
                offset = child_value.find(b"\x7f\x21")
                if offset >= 0:
                    cvc = child_value[offset:]
                    parse_cvc(cvc, "secure_messaging_cvc")
                    return cvc
    raise ValueError("source vector does not contain a secure messaging CVC")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def vector_label(path: Path) -> str:
    card = re.search(r"card_?(\d+)", path.stem)
    if card:
        return f"card-{int(card.group(1))}"
    return path.stem.replace("_", "-")


def import_sd33_vector(path: Path, output_root: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    smcs = find_smcs(data)
    secure_cvc = find_secure_cvc(data)
    smcs_info = parse_smcs(smcs)
    if smcs_info["certificate"] is None:
        raise ValueError(f"{path} 5FC122 does not contain a content-signing certificate")

    trust_anchor, _summary = build_record(smcs_info["certificate"])
    parsed_cvc = parse_cvc(secure_cvc, "secure_messaging_cvc")
    has_intermediate = smcs_info["intermediate_raw"] is not None
    suffix = "intermediate" if has_intermediate and parsed_cvc["iin"] != trust_anchor_iin(trust_anchor) else "direct"
    out_dir = output_root / f"{vector_label(path)}-{suffix}"
    out_dir.mkdir(parents=True, exist_ok=True)

    shutil.copyfile(path, out_dir / "source-vector.json")
    (out_dir / "secure-messaging-cvc-7f21.bin").write_bytes(secure_cvc)
    (out_dir / "smcs-5fc122.bin").write_bytes(smcs)
    (out_dir / "content-signing-certificate.der").write_bytes(smcs_info["certificate_der"])
    (out_dir / "vci-trust-anchor-record.bin").write_bytes(trust_anchor)
    if smcs_info["intermediate_raw"] is not None:
        (out_dir / "intermediate-cvc-7f21.bin").write_bytes(smcs_info["intermediate_raw"])

    report = validate(
        Namespace(
            anchor=str((out_dir / "vci-trust-anchor-record.bin").relative_to(REPO_ROOT)),
            cvc=str((out_dir / "secure-messaging-cvc-7f21.bin").relative_to(REPO_ROOT)),
            smcs=str((out_dir / "smcs-5fc122.bin").relative_to(REPO_ROOT)),
            ca_bundle=None,
            validation_time=None,
        )
    )
    report["source_fixture"] = {
        "source_file": path.name,
        "source_sha256": sha256_file(path),
        "public_test_fixture": True,
        "warning": (
            "This byte-complete source vector may contain PINs, pairing codes, ephemeral private keys, "
            "shared secrets, and derived session keys from public test cards. Do not use it as operational secret material."
        ),
    }
    write_json(out_dir / "validation-report.json", report)
    return {
        "source": "source-vector.json",
        "source_sha256": report["source_fixture"]["source_sha256"],
        "output": str(out_dir.relative_to(REPO_ROOT)),
        "validation_passed": report["result"]["passed"],
        "pd_path": report["pd_validation"]["path"],
        "secure_cvc_iin": report["reported_to_acu"]["vci_cvc_iin"],
        "anchor_iin": report["reported_to_acu"]["vci_anchor_iin"],
    }


def trust_anchor_iin(record: bytes) -> bytes:
    tag, _length, value, _tlv, end = read_tlv(record, 0)
    if tag != b"\x7f\x50" or end != len(record):
        raise ValueError("trust anchor must be a single 7F50 record")
    fields = {child_tag: child_value for child_tag, _child_length, child_value, _child_tlv in children(value)}
    return fields[b"\x42"]


def import_sm_vci_corpus(path: Path, output_root: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    secure_cvc = find_secure_cvc(data)
    parsed = parse_cvc(secure_cvc, "secure_messaging_cvc")
    out_dir = output_root / path.stem.replace("_", "-")
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, out_dir / "source-vector.json")
    (out_dir / "secure-messaging-cvc-7f21.bin").write_bytes(secure_cvc)
    metadata = {
        "source": "source-vector.json",
        "source_sha256": sha256_file(path),
        "public_test_fixture": True,
        "secure_cvc": {
            "length": parsed["length"],
            "iin": parsed["iin"].hex().upper(),
            "subject_identifier": parsed["subject_identifier"].hex().upper(),
            "role": parsed["role"].hex().upper(),
            "public_key_curve_oid": parsed["public_key_curve_oid"],
            "signature_algorithm_oid": parsed["signature_algorithm_oid"],
        },
        "note": (
            "This public test fixture preserves the CVC from the VCI vector. It may preserve byte-complete "
            "test-card capture material and does not include anchor validation material."
        ),
    }
    write_json(out_dir / "metadata.json", metadata)
    return {
        "source": "source-vector.json",
        "source_sha256": metadata["source_sha256"],
        "output": str(out_dir.relative_to(REPO_ROOT)),
        "secure_cvc_iin": metadata["secure_cvc"]["iin"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sd33-dir", type=Path, default=DEFAULT_SD33_DIR)
    parser.add_argument("--sm-vci-dir", type=Path, default=DEFAULT_SM_VCI_DIR)
    parser.add_argument("--anchor-output", type=Path, default=DEFAULT_ANCHOR_OUTPUT)
    parser.add_argument("--cvc-corpus-output", type=Path, default=DEFAULT_CVC_CORPUS_OUTPUT)
    parser.add_argument("--skip-sm-vci-corpus", action="store_true")
    args = parser.parse_args()

    sd33_paths = sorted(args.sd33_dir.glob("nist_special_database_33_card_*.json"))
    sm_vci_paths: list[Path] = []
    if not args.skip_sm_vci_corpus:
        for pattern in ("vci_vectors_*.json", "vci_contactless_*.json"):
            sm_vci_paths.extend(sorted(args.sm_vci_dir.glob(pattern)))
    if not sd33_paths and not sm_vci_paths:
        searched = [str(args.sd33_dir)]
        if not args.skip_sm_vci_corpus:
            searched.append(str(args.sm_vci_dir))
        raise SystemExit(f"no VCI vector source files found in: {', '.join(searched)}")

    imported = {"trust_anchor_vectors": [], "cvc_corpus": []}
    for path in sd33_paths:
        imported["trust_anchor_vectors"].append(import_sd33_vector(path, args.anchor_output))

    if not args.skip_sm_vci_corpus:
        for path in sm_vci_paths:
            imported["cvc_corpus"].append(import_sm_vci_corpus(path, args.cvc_corpus_output))

    print(json.dumps(imported, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
