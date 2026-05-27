# PIV Auto Demonstration Fixtures

This folder contains reusable demonstration keys and certificates for `scripts/simulate_piv_auto.py`.

These files are copied from `~/Projects/gsa-icam-card-builder/` and are intentionally reusable test material. They are not production credentials and must not be treated as trusted operational keys.

## Fixture Roles

- `source-p12/root-ca.p12`: root CA private key and certificate.
- `source-p12/intermediate-ca-rsa2048.p12`: RSA-2048 intermediate CA private key and certificate. The simulator converts this certificate into the trust-anchor record loaded into the PD.
- `source-p12/intermediate-cvc-signer-p256.p12`: EC P-256 intermediate CVC signer private key and certificate.
- `source-p12/card-auth.p12`: simulated credential Card Authentication private key and certificate.
- `certs/*.crt`: matching PEM certificates copied from the same source project.
- `generated/`: deterministic simulator outputs written by `scripts/simulate_piv_auto.py`.

All PKCS#12 files use an empty password, matching the card-builder `passcode=` convention.

## Run From Repository Root

```bash
python3 scripts/simulate_piv_auto.py \
  --output test-vectors/piv-auto-demo/generated/piv-auto-simulation-report.json
```

Expected result:

- `summary.status`: `passed`
- `pd_validation.intermediate_cvc.signature_verified_with_loaded_anchor`: `true`
- `pd_validation.secure_cvc.signature_verified_with_intermediate_cvc`: `true`
- `acu_validation.card_response_signature_verified`: `true`
- `poll_response.reply_code`: `0x89`

Negative examples:

```bash
python3 scripts/simulate_piv_auto.py --negative factory-key
python3 scripts/simulate_piv_auto.py --negative duplicate-counter
python3 scripts/simulate_piv_auto.py --negative tampered-response
python3 scripts/simulate_piv_auto.py --negative wrong-anchor
python3 scripts/simulate_piv_auto.py --negative missing-intermediate-cvc
```
