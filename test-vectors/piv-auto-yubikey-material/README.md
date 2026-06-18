# PIV Auto YubiKey Material

This directory contains reusable generated private keys and self-signed
certificates for PIV Auto YubiKey loading tests. These are public test
fixtures and must not be used for production credentials.

Included profiles:

- `9a-rsa1024`, `9e-rsa1024`: legacy RSA-1024 test coverage.
- `9a-rsa3072`, `9e-rsa3072`: RSA-3072 coverage.
- `9a-ecp384`, `9e-ecp384`: ECC P-384 PIV Auto coverage.
- `9c-ecp384`, `9d-ecp384`: supporting P-384 APDU examples.

Load one profile with:

```bash
PIV_PIN=123456 PIV_MANAGEMENT_KEY=<hex-management-key> \
  PIV_PROFILES=9e-rsa1024 make live-piv-auto
```

The make target calls `scripts/load_ykman_committed_material.sh`, which invokes
`ykman piv` directly for the committed keys and certificates.

Firmware note: YubiKey 5.4.3 accepts the RSA-1024 and P-384 fixtures, but
rejects RSA-3072 with `RSA3072 requires YubiKey 5.7 or later`. The RSA-3072
fixtures remain committed for devices that support that key size.
