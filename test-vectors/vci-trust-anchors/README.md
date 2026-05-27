# VCI Trust Anchor Test Vectors

This folder contains the NIST SD 33 vector source data and the generated VCI trust anchor records used by the proposal examples and validation scripts.

## Layout

Each card folder contains:

- `source-vector.json`: original NIST SD 33 card vector JSON.
- `content-signing-certificate.der`: X.509 content-signing certificate extracted from `5FC122`.
- `secure-messaging-cvc-7f21.bin`: secure messaging CVC object.
- `smcs-5fc122.bin`: Secure Messaging Certificate Signer object, including the content-signing certificate and, when present, an Intermediate CVC.
- `vci-trust-anchor-record.bin`: generated binary `7F50` VCI trust anchor record.

## Included Cases

| Folder | Source Vector | Flow | Content Signer | Anchor IIN | CVC IIN | Anchor Length |
| --- | --- | --- | --- | --- | --- | --- |
| `card-4-ec-direct` | `nist_special_database_33_card_4.json` | Direct EC P-256 | `CN=Test PIV Content Signer 3` | `1905976BDDCA823D` | `1905976BDDCA823D` | 110 |
| `card-16-rsa-intermediate` | `nist_special_database_33_card_16.json` | RSA-2048 anchor with Intermediate CVC | `CN=Test PIV-I Content Signer 1` | `4CC9C7B3A4F1C83E` | `6F8FF48F42B3E22E` | 317 |

## Reproduce Trust Anchor Records

```bash
scripts/make_vci_trust_anchor.py \
  test-vectors/vci-trust-anchors/card-4-ec-direct/content-signing-certificate.der \
  /tmp/card4.anchor

scripts/make_vci_trust_anchor.py \
  test-vectors/vci-trust-anchors/card-16-rsa-intermediate/content-signing-certificate.der \
  /tmp/card16.anchor
```

## Validate Chains

```bash
scripts/validate_vci_chain.py \
  --anchor test-vectors/vci-trust-anchors/card-4-ec-direct/vci-trust-anchor-record.bin \
  --cvc test-vectors/vci-trust-anchors/card-4-ec-direct/secure-messaging-cvc-7f21.bin

scripts/validate_vci_chain.py \
  --anchor test-vectors/vci-trust-anchors/card-16-rsa-intermediate/vci-trust-anchor-record.bin \
  --cvc test-vectors/vci-trust-anchors/card-16-rsa-intermediate/secure-messaging-cvc-7f21.bin \
  --smcs test-vectors/vci-trust-anchors/card-16-rsa-intermediate/smcs-5fc122.bin
```

The direct EC case does not require `5FC122` for PD validation. The RSA case requires `5FC122` because the secure messaging CVC is signed by an Intermediate CVC rather than directly by the loaded trust anchor.
