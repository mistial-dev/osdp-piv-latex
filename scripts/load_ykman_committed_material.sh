#!/usr/bin/env bash
set -euo pipefail

material_dir="${MATERIAL_DIR:-test-vectors/piv-auto-yubikey-material}"
profiles_csv="${PIV_PROFILES:-9e-rsa1024}"

if [[ -z "${PIV_PIN:-}" || -z "${PIV_MANAGEMENT_KEY:-}" ]]; then
  echo "PIV_PIN and PIV_MANAGEMENT_KEY must be set before writing YubiKey PIV slots." >&2
  exit 1
fi

IFS=',' read -r -a profiles <<< "${profiles_csv}"

for profile in "${profiles[@]}"; do
  profile="${profile//[[:space:]]/}"
  [[ -n "${profile}" ]] || continue

  case "${profile}" in
    9a-*)
      slot="9a"
      pin_policy="ONCE"
      ;;
    9c-*)
      slot="9c"
      pin_policy="ALWAYS"
      ;;
    9d-*)
      slot="9d"
      pin_policy="ONCE"
      ;;
    9e-*)
      slot="9e"
      pin_policy="NEVER"
      ;;
    *)
      echo "Unsupported committed PIV profile: ${profile}" >&2
      exit 1
      ;;
  esac

  key_path="${material_dir}/${profile}/private-key.pem"
  cert_path="${material_dir}/${profile}/certificate.pem"
  if [[ ! -f "${key_path}" || ! -f "${cert_path}" ]]; then
    echo "Missing committed key or certificate for ${profile} under ${material_dir}." >&2
    exit 1
  fi

  echo "Loading ${profile} into PIV slot ${slot^^}."
  ykman piv keys import \
    --pin "${PIV_PIN}" \
    --management-key "${PIV_MANAGEMENT_KEY}" \
    --pin-policy "${pin_policy}" \
    --touch-policy NEVER \
    "${slot}" \
    "${key_path}"
  ykman piv certificates import \
    --pin "${PIV_PIN}" \
    --management-key "${PIV_MANAGEMENT_KEY}" \
    --verify \
    --compress \
    "${slot}" \
    "${cert_path}"
done
