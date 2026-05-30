# OSDP PIV Helper Scripts

This folder contains small helper tools used to generate and check the VCI trust-anchor examples in the proposal.

The examples below are written to be copied from this `scripts/` directory.

## Dependencies

From the repository root:

```bash
python3 -m pip install -r requirements.txt
```

## `make_vci_trust_anchor.py`

Creates a binary BER-TLV VCI trust anchor record from an X.509 content-signing certificate in PEM or DER form.
Records are variable length. The script writes the exact BER-TLV record length required for the certificate public key and rejects records larger than `0x0240` bytes.

The output record is:

```text
7F50
  80 01 01
  42 08 <leftmost 8 bytes of certificate Subject Key Identifier>
  7F49 <DER SubjectPublicKeyInfo>
```

Supported public keys:

- RSA through 4096 bits.
- EC P-256 and P-384.

Example, direct EC anchor from NIST SD 33 card 4:

```bash
./make_vci_trust_anchor.py \
  ../test-vectors/vci-trust-anchors/card-4-direct/content-signing-certificate.der \
  /tmp/card4-vci-trust-anchor.bin
```

Expected summary values:

- `summary.status`: `created`
- `trust_anchor_record.iin`: `1905976BDDCA823D`
- `trust_anchor_record.algorithm`: `EC-secp256r1`
- `trust_anchor_record.spki_length`: `91`
- `trust_anchor_record.record_length`: `110`

Example, RSA anchor from NIST SD 33 card 16:

```bash
./make_vci_trust_anchor.py \
  ../test-vectors/vci-trust-anchors/card-16-intermediate/content-signing-certificate.der \
  /tmp/card16-vci-trust-anchor.bin
```

Expected summary values:

- `summary.status`: `created`
- `trust_anchor_record.iin`: `4CC9C7B3A4F1C83E`
- `trust_anchor_record.algorithm`: `RSA-2048`
- `trust_anchor_record.spki_length`: `294`
- `trust_anchor_record.record_length`: `317`

## `validate_vci_chain.py`

Validates the PD-visible CVC chain and emits JSON that separates what the PD validates from what the ACU validates or must still validate.

Inputs:

- `--anchor`: binary trust-anchor record file or hex string.
- `--cvc`: secure messaging CVC `7F21` file or hex string.
- `--smcs`: optional Secure Messaging Certificate Signer object, `5FC122` or inner `53`, file or hex string.
- `--ca-bundle`: optional PEM/DER issuer bundle for ACU path checking.
- `--validation-time`: optional ISO-8601 validation time for ACU certificate validity checking.
- `--output`: optional path to write the same readable JSON report that is printed to stdout.

Direct EC example:

```bash
./validate_vci_chain.py \
  --anchor ../test-vectors/vci-trust-anchors/card-4-direct/vci-trust-anchor-record.bin \
  --cvc ../test-vectors/vci-trust-anchors/card-4-direct/secure-messaging-cvc-7f21.bin \
  --output ../test-vectors/vci-trust-anchors/card-4-direct/validation-report.json
```

Expected result:

- `summary.status`: `passed`
- `summary.pd_path`: `direct`
- `result.passed`: `true`
- `pd_validation.path`: `direct`
- `reported_to_acu.vci_cvc_iin`: `1905976BDDCA823D`
- `reported_to_acu.vci_anchor_iin`: `1905976BDDCA823D`

RSA intermediate example:

```bash
./validate_vci_chain.py \
  --anchor ../test-vectors/vci-trust-anchors/card-16-intermediate/vci-trust-anchor-record.bin \
  --cvc ../test-vectors/vci-trust-anchors/card-16-intermediate/secure-messaging-cvc-7f21.bin \
  --smcs ../test-vectors/vci-trust-anchors/card-16-intermediate/smcs-5fc122.bin \
  --output ../test-vectors/vci-trust-anchors/card-16-intermediate/validation-report.json
```

Expected result:

- `summary.status`: `passed`
- `summary.pd_path`: `intermediate`
- `result.passed`: `true`
- `pd_validation.path`: `intermediate`
- `reported_to_acu.vci_cvc_iin`: `6F8FF48F42B3E22E`
- `reported_to_acu.vci_anchor_iin`: `4CC9C7B3A4F1C83E`

The validator exits with:

- `0` when validation passes.
- `1` when input parsing or command execution fails.
- `2` when inputs parse correctly but the CVC chain does not validate.

The PD validation section intentionally checks only the immediate signer of the secure messaging CVC: either the loaded anchor directly, or an Intermediate CVC verified by the loaded anchor. The ACU validation section reports the X.509 chain, time, policy, and revocation work that is outside the PD validation scope.

## `import_vci_vector_fixtures.py`

Imports available NIST test-card VCI vector material into repository fixtures.

The committed fixture directories include their source capture JSON as
`source-vector.json`, so the documentation and validation reports are
self-contained inside this repository. Validation reports and corpus metadata
include the SHA-256 hash of the copied source vector used for regeneration
auditing.

For regeneration, provide local capture directories with `--sd33-dir` and
`--sm-vci-dir`. By default the script uses the sibling capture directories in
the working tree when they are present.

It imports validator-ready trust-anchor examples with `5FC122` and a CVC
parsing corpus from contact/contactless VCI capture JSON. These byte-complete
public test fixtures may contain PINs, pairing codes, ephemeral private keys,
shared secrets, and derived session keys from public test cards; they are not
operational secret material.

Run from the repository root:

```bash
scripts/import_vci_vector_fixtures.py
```

Live captures from local NIST PIV test cards can be imported by rerunning this
script with the capture directory paths. The GSA FICAM card-builder material
remains the source for reusable PIV Auto card-authentication keys and
certificates; the committed CVC bytes come from NIST test-card vector captures,
not from synthetic CVC generation.

## `import_nist_sd33_vectors.py`

Imports local NIST SD 33 / IR 8347 APDU transcript JSON for cards 2, 3, 4, 5,
and 16 into `test-vectors/nist-sd33-apdu/`. These fixtures provide the primary
hardware-free replay corpus for OPACITY/VCI and PIV `GENERAL AUTHENTICATE`
operations.

Run from the repository root:

```bash
python3 scripts/import_nist_sd33_vectors.py
```

## `replay_piv_auto_apdu_fixtures.py`

Replays committed APDU transcript fixtures and verifies that every
`GENERAL AUTHENTICATE` command and Dynamic Authentication Template response
parses correctly.

```bash
python3 scripts/replay_piv_auto_apdu_fixtures.py
```

Expected result:

- `summary.status`: `passed`
- `summary.general_authenticate_count`: non-zero; currently 80 for the imported
  NIST SD 33 fixtures.

## `render_piv_auto_appendix_tables.py`

Regenerates the Appendix C worked PIV Auto example tables from the verified
simulation report. The generated tables include the KMAC challenge digest,
tag `81` challenge input, full `GENERAL AUTHENTICATE` APDU, dynamic
authentication response, and tag `82` length for each supported profile.

```bash
python3 scripts/render_piv_auto_appendix_tables.py
python3 scripts/render_piv_auto_appendix_tables.py --check
```

Expected result:

- `tables/piv-auto-worked-examples.tex` matches the committed simulation
  report.
- `--check` exits with `0` when the table fragment is current.

## `load_ykman_piv_profiles.py`

Generates test keys/certificates for PIV Auto profiles and loads them into
YubiKey PIV slots through `ykman piv`. The command is guarded: use `--dry-run`
to generate material and print redacted commands, or pass `--overwrite` to
actually write slots.

Secrets are supplied by `PIV_PIN` and `PIV_MANAGEMENT_KEY` or by explicit
arguments. Generated private keys are written under `build/` by default.
Reusable committed test material for missing profiles is under
`test-vectors/piv-auto-yubikey-material/`; these private keys are public test
fixtures and must not be used for production credentials.

```bash
PIV_PIN=123456 PIV_MANAGEMENT_KEY=010203040506070801020304050607080102030405060708 \
  python3 scripts/load_ykman_piv_profiles.py --dry-run --profiles 9e-rsa2048,9e-ecp256
```

Load the committed RSA-1024 Card Authentication profile:

```bash
PIV_PIN=123456 PIV_MANAGEMENT_KEY=<hex-management-key> \
  PIV_PROFILES=9e-rsa1024 make live-piv-auto
```

`make live-piv-auto` uses `scripts/load_ykman_committed_material.sh`, which
invokes `ykman` directly against the committed material. Keep using the Python
loader when generating new material or producing a dry-run report.

The committed material covers missing generated-card profiles:
`9a-rsa1024`, `9e-rsa1024`, `9a-rsa3072`, `9e-rsa3072`, `9a-ecp384`,
`9e-ecp384`, plus supporting `9c-ecp384` and `9d-ecp384` examples.
YubiKey 5.4.3 rejects RSA-3072 imports; use YubiKey 5.7 or later for those
profiles.

## `capture_piv_auto_apdus.py`

Captures live `GENERAL AUTHENTICATE` APDUs from a PC/SC card. This optional
tool requires `pyscard`; normal repository tests do not require hardware.

```bash
python3 scripts/capture_piv_auto_apdus.py \
  --profile 9e-ecp256 \
  --input-hex 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF \
  --out test-vectors/piv-auto-apdu/live-capture.json
```

## `simulate_piv_auto.py`

Simulates the proposed PIV Auto flow with real cryptography and emits a readable JSON log. The script does not parse raw OSDP packets; it logs representative ACU, PD, and card steps while deriving the PIV Auto KDK from simulated SC2 session keys, deriving the KMAC256 challenge, validating CVC signatures, signing with the card authentication key, and verifying the final response.

The demo uses reusable no-password PKCS#12 fixtures under
`../test-vectors/piv-auto-demo/`, copied from GSA FICAM card-builder material.

Run the positive flow from this `scripts/` directory:

```bash
./simulate_piv_auto.py \
  --all-profiles \
  --sc2-session-keys 00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0FFFEEDDCCBBAA99887766554433221100 \
  --output ../test-vectors/piv-auto-demo/generated/piv-auto-simulation-report.json
```

Expected result:

- `summary.status`: `passed`
- `pd_validation.intermediate_cvc.signature_verified_with_loaded_anchor`: `true`
- `pd_validation.secure_cvc.signature_verified_with_intermediate_cvc`: `true`
- `acu_validation.card_response_signature_verified`: `true`
- `poll_response.reply_code`: `0x89`
- `profile_coverage[*].verified`: `true`

Run negative examples:

```bash
./simulate_piv_auto.py --negative factory-key
./simulate_piv_auto.py --negative duplicate-counter
./simulate_piv_auto.py --negative tampered-response
./simulate_piv_auto.py --negative wrong-anchor
./simulate_piv_auto.py --negative missing-intermediate-cvc
```
