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
  ../test-vectors/vci-trust-anchors/card-4-ec-direct/content-signing-certificate.der \
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
  ../test-vectors/vci-trust-anchors/card-16-rsa-intermediate/content-signing-certificate.der \
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
  --anchor ../test-vectors/vci-trust-anchors/card-4-ec-direct/vci-trust-anchor-record.bin \
  --cvc ../test-vectors/vci-trust-anchors/card-4-ec-direct/secure-messaging-cvc-7f21.bin \
  --output ../test-vectors/vci-trust-anchors/card-4-ec-direct/validation-report.json
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
  --anchor ../test-vectors/vci-trust-anchors/card-16-rsa-intermediate/vci-trust-anchor-record.bin \
  --cvc ../test-vectors/vci-trust-anchors/card-16-rsa-intermediate/secure-messaging-cvc-7f21.bin \
  --smcs ../test-vectors/vci-trust-anchors/card-16-rsa-intermediate/smcs-5fc122.bin \
  --output ../test-vectors/vci-trust-anchors/card-16-rsa-intermediate/validation-report.json
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

## `simulate_piv_auto.py`

Simulates the proposed PIV Auto flow with real cryptography and emits a readable JSON log. The script does not parse raw OSDP packets; it logs representative ACU, PD, and card steps while actually deriving the KMAC256 challenge, validating CVC signatures, signing with the card authentication key, and verifying the final response.

The demo uses reusable no-password PKCS#12 fixtures under `../test-vectors/piv-auto-demo/`, copied from `~/Projects/gsa-icam-card-builder/`.

Run the positive flow from this `scripts/` directory:

```bash
./simulate_piv_auto.py \
  --output ../test-vectors/piv-auto-demo/generated/piv-auto-simulation-report.json
```

Expected result:

- `summary.status`: `passed`
- `pd_validation.intermediate_cvc.signature_verified_with_loaded_anchor`: `true`
- `pd_validation.secure_cvc.signature_verified_with_intermediate_cvc`: `true`
- `acu_validation.card_response_signature_verified`: `true`
- `poll_response.reply_code`: `0x89`

Run negative examples:

```bash
./simulate_piv_auto.py --negative factory-key
./simulate_piv_auto.py --negative duplicate-counter
./simulate_piv_auto.py --negative tampered-response
./simulate_piv_auto.py --negative wrong-anchor
./simulate_piv_auto.py --negative missing-intermediate-cvc
```
