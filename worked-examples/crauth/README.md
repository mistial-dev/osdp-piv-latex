# CRAUTH format and completion examples

The command remains 0xA5. The OSDP 3.0 logical request is:

`FF | Algorithm | Key Reference | Challenge`

Multipart total, offset, and size count every byte of this record. The first
fragment in the success example contains only FF; Algorithm and Key Reference
follow in the second fragment. The marker is removed before constructing the
credential command. A first byte other than FF identifies the old form, which
the bounded new-only PD model rejects. Legacy command execution is outside this model.

The success reuses the card04 contactless SM capture's P-256 challenge and
complete response template. It assumes credential SM is already established.
The incorrect-security-state and mid-delivery timeout outcomes are modeled;
both end with one PIVERROR. Partial response data is discarded on failure.
These examples omit OSDP Secure Channel for clarity.

From the repository root:

```sh
python3 scripts/crauth_examples.py
python3 scripts/check_crauth_examples.py
python3 scripts/render_crauth_examples.py
```

The independent checker validates CRCs, sequence numbers, packet lengths,
multipart accounting, source APDUs, captured SM cryptography, and terminal
error handling. No new credential capture is performed.
