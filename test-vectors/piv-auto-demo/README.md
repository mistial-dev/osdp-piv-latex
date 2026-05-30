# PIV Auto Demonstration Fixtures

This folder contains reusable demonstration keys, certificates, and imported CVC material for
`scripts/simulate_piv_auto.py`.

The PKCS#12 keys and matching PEM certificates are reusable test material
originally imported from GSA FICAM card-builder and committed with this
repository. They are not production credentials and must not be treated as
trusted operational keys.

The generated CVC and VCI trust-anchor bytes come from NIST test-card VCI
captures, not from synthetic CVC generation.

Additional raw APDU fixtures from NIST SD 33 / IR 8347 cards are imported under
`test-vectors/nist-sd33-apdu/` and replayed by
`scripts/replay_piv_auto_apdu_fixtures.py`.

Reusable generated YubiKey PIV key material for profiles not backed by the
NIST/GSA fixtures is stored under `test-vectors/piv-auto-yubikey-material/`.
Those private keys are committed public test fixtures, including RSA-1024,
RSA-3072, and ECC P-384 profiles, and must not be used for production
credentials. RSA-1024 material is retained only for informative
legacy/non-current examples and is not a supported PIV Auto profile.

## Fixture Roles

- `source-p12/root-ca.p12`: root CA private key and certificate.
- `source-p12/intermediate-ca-rsa2048.p12`: RSA-2048 intermediate CA private key and certificate. The simulator converts this certificate into the trust-anchor record loaded into the PD.
- `source-p12/intermediate-cvc-signer-p256.p12`: EC P-256 intermediate CVC signer private key and certificate.
- `source-p12/card-auth.p12`: simulated credential Card Authentication private key and certificate.
- `certs/*.crt`: matching PEM certificates copied from the same source project.
- `generated/`: deterministic simulator outputs written by `scripts/simulate_piv_auto.py`.
  The CVC, SMCS, and VCI trust-anchor files are imported from
  `test-vectors/vci-trust-anchors/card-16-intermediate`, which is derived
  from NIST test-card VCI capture data. The simulator does not synthesize CVC
  `7F49` public-key objects.

All PKCS#12 files use an empty password, matching the card-builder `passcode=` convention.

## Run From Repository Root

```bash
python3 scripts/simulate_piv_auto.py \
  --all-profiles \
  --sc2-session-keys 00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0FFFEEDDCCBBAA99887766554433221100 \
  --output test-vectors/piv-auto-demo/generated/piv-auto-simulation-report.json
```

Validate the generated CVC chain:

```bash
python3 scripts/validate_vci_chain.py \
  --anchor test-vectors/piv-auto-demo/generated/loaded-intermediate-ca-trust-anchor.bin \
  --cvc test-vectors/piv-auto-demo/generated/secure-card-cvc-7f21.bin \
  --smcs test-vectors/piv-auto-demo/generated/smcs-5fc122.bin
```

Expected result:

- `summary.status`: `passed`
- `pd_validation.intermediate_cvc.signature_verified_with_loaded_anchor`: `true`
- `pd_validation.secure_cvc.signature_verified_with_intermediate_cvc`: `true`
- `acu_validation.card_response_signature_verified`: `true`
- `profile_coverage[*].verified`: `true`
- `poll_response.reply_code`: `0x89`

Negative examples:

```bash
python3 scripts/simulate_piv_auto.py --negative factory-key
python3 scripts/simulate_piv_auto.py --negative duplicate-counter
python3 scripts/simulate_piv_auto.py --negative tampered-response
python3 scripts/simulate_piv_auto.py --negative wrong-anchor
python3 scripts/simulate_piv_auto.py --negative missing-intermediate-cvc
```
