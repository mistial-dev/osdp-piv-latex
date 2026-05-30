#!/usr/bin/env python3
"""Generate and load PIV Auto test keys into YubiKey PIV slots."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from piv_auto_apdu import PIV_AUTO_PROFILE_IDS, PROFILES


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "build" / "generated-piv-auto-yubikey"
DEFAULT_SUBJECT = "OSDP PIV Auto Generated Test"


def generate_private_key(key_type: str):
    if key_type == "rsa1024":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa3072":
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if key_type == "ecp256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ecp384":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError(f"unsupported key type: {key_type}")


def self_signed_cert(private_key, profile_id: str, subject_prefix: str) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OSDP PIV Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{subject_prefix} {profile_id}"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )


def pin_policy(profile_id: str) -> str:
    slot = profile_id[:2]
    if slot == "9e":
        return "NEVER"
    if slot == "9c":
        return "ALWAYS"
    return "ONCE"


def write_material(out_dir: Path, profile_id: str, private_key, cert: x509.Certificate) -> tuple[Path, Path]:
    profile_dir = out_dir / profile_id
    profile_dir.mkdir(parents=True, exist_ok=True)
    key_path = profile_dir / "private-key.pem"
    cert_path = profile_dir / "certificate.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def material_paths(material_dir: Path, profile_id: str) -> tuple[Path, Path]:
    profile_dir = material_dir / profile_id
    return profile_dir / "private-key.pem", profile_dir / "certificate.pem"


def ykman_command(args: argparse.Namespace, profile_id: str, key_path: Path, cert_path: Path) -> list[list[str]]:
    profile = PROFILES[profile_id]
    slot = f"{profile.key_ref:02x}"
    base_secret = ["--pin", args.pin, "--management-key", args.management_key]
    return [
        [
            "ykman",
            "piv",
            "keys",
            "import",
            *base_secret,
            "--pin-policy",
            pin_policy(profile_id),
            "--touch-policy",
            "NEVER",
            slot,
            str(key_path),
        ],
        [
            "ykman",
            "piv",
            "certificates",
            "import",
            *base_secret,
            "--verify",
            "--compress",
            slot,
            str(cert_path),
        ],
    ]


def redacted(command: list[str]) -> list[str]:
    out = []
    skip_next = False
    secret_flags = {"--pin", "--management-key"}
    for token in command:
        if skip_next:
            out.append("<redacted>")
            skip_next = False
        else:
            out.append(token)
            skip_next = token in secret_flags
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", default=",".join(PIV_AUTO_PROFILE_IDS))
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--material-dir",
        type=Path,
        help="Load existing profile private-key.pem/certificate.pem pairs instead of generating new material",
    )
    parser.add_argument(
        "--write-material",
        type=Path,
        help="Generate profile private-key.pem/certificate.pem pairs into this directory and write a manifest",
    )
    parser.add_argument("--subject-prefix", default=DEFAULT_SUBJECT)
    parser.add_argument("--pin", default=os.environ.get("PIV_PIN"))
    parser.add_argument("--management-key", default=os.environ.get("PIV_MANAGEMENT_KEY"))
    parser.add_argument("--dry-run", action="store_true", help="Generate material and print ykman commands without writing slots")
    parser.add_argument("--overwrite", action="store_true", help="Required before invoking ykman slot writes")
    args = parser.parse_args()

    if not args.pin or not args.management_key:
        print("PIV_PIN and PIV_MANAGEMENT_KEY must be supplied via env or arguments", file=sys.stderr)
        return 1
    if not args.dry_run and not args.overwrite:
        print("--overwrite is required unless --dry-run is used", file=sys.stderr)
        return 1

    selected = [item.strip() for item in args.profiles.split(",") if item.strip()]
    material_root = args.material_dir or args.write_material
    report = {
        "summary": {
            "status": "running",
            "profiles": selected,
            "material_dir": str(material_root) if material_root else None,
        },
        "profiles": [],
    }
    for profile_id in selected:
        profile = PROFILES[profile_id]
        if args.material_dir:
            key_path, cert_path = material_paths(args.material_dir, profile_id)
            if not key_path.exists() or not cert_path.exists():
                raise FileNotFoundError(f"missing material for {profile_id} under {args.material_dir}")
        else:
            private_key = generate_private_key(profile.key_type)
            cert = self_signed_cert(private_key, profile_id, args.subject_prefix)
            key_path, cert_path = write_material(args.write_material or args.out_dir, profile_id, private_key, cert)
        commands = ykman_command(args, profile_id, key_path, cert_path)
        entry = {
            "profile": profile_id,
            "slot": f"{profile.key_ref:02X}",
            "algorithm_id": f"0x{profile.algorithm_id:02X}",
            "key_type": profile.key_type,
            "key_path": str(key_path),
            "cert_path": str(cert_path),
            "commands": [redacted(command) for command in commands],
            "loaded": False,
        }
        if not args.dry_run:
            for command in commands:
                subprocess.run(command, check=True)
            entry["loaded"] = True
        report["profiles"].append(entry)

    report["summary"]["status"] = "planned" if args.dry_run else "loaded"
    if args.write_material:
        manifest = {
            "source": "Generated reusable YubiKey PIV test material for OSDP PIV Auto coverage.",
            "warning": "These private keys are committed test fixtures. Do not use them for production credentials.",
            "loader": "scripts/load_ykman_piv_profiles.py",
            "profiles": [
                {
                    "profile": entry["profile"],
                    "slot": entry["slot"],
                    "algorithm_id": entry["algorithm_id"],
                    "key_type": entry["key_type"],
                    "pin_policy": pin_policy(entry["profile"]),
                    "touch_policy": "NEVER",
                    "private_key": f"{entry['profile']}/private-key.pem",
                    "certificate": f"{entry['profile']}/certificate.pem",
                }
                for entry in report["profiles"]
            ],
        }
        args.write_material.mkdir(parents=True, exist_ok=True)
        (args.write_material / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        readme = (
            "# PIV Auto YubiKey Material\n\n"
            "This directory contains reusable generated private keys and self-signed\n"
            "certificates for PIV Auto YubiKey loading tests. These are public test\n"
            "fixtures and must not be used for production credentials.\n\n"
            "Load one profile with:\n\n"
            "```bash\n"
            "PIV_PIN=123456 PIV_MANAGEMENT_KEY=<hex-management-key> \\\n"
            "  python3 scripts/load_ykman_piv_profiles.py \\\n"
            "  --material-dir test-vectors/piv-auto-yubikey-material \\\n"
            "  --profiles 9e-rsa1024 --overwrite\n"
            "```\n"
        )
        (args.write_material / "README.md").write_text(readme, encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
