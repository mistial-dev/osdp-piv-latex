# Credential SM and VCI examples

These examples omit OSDP Secure Channel for clarity. They use a simulated ACU
and PD, with APDUs replayed from the repository's existing card captures.
No reader, PC/SC connection, or new card capture is used.

Run from the repository root, with `cryptography` installed:

```sh
python3 scripts/sm_vci_replay.py --output worked-examples/sm-vci/examples.json
python3 scripts/check_sm_vci_examples.py
PYTHONPATH=scripts python3 -m unittest discover -s scripts/tests -p 'test_sm_vci_replay.py'
```

## What the examples establish

`contact-sm` reports SM established over contact, with VCI absent.
`contactless-pairing` reports SM-only readiness, accepts the pairing command,
and completes with SM and VCI available on a later poll.
`cache-before-card` collects the test PIN before card presentation, preserves
it through initial preparation, and verifies it after commanded pairing.

The verifier checks the captured CVC signature against the existing
`card-2-direct` trust anchor. It recomputes ECDH, the session-key KDF and the
authentication cryptogram. For every protected logical exchange, it checks
command MAC, response MAC, ciphertext/plaintext, and counter/MCV progression.
It also checks source hashes and exact APDU correspondence. OSDP CRCs use an
independent implementation (`binascii.crc_hqx`).

The failure examples demonstrate proposed result encodings. Their failure
conditions are modeled; separate corruption tests demonstrate actual verifier
rejection of altered CVC signatures, cryptograms, and response MACs.

`diagnostic-empty-store` reports that setup was skipped and no CVC was received.
`diagnostic-cvc-hash` demonstrates a modeled cryptogram failure, followed by
CARDSTATUS type `0x02`. Each CARDSTATUSR fragment carries type `0x02` immediately
after reply code `0x85`, followed by the multipart fields. Three replies reassemble
the 35-byte diagnostic record; the repeated type byte is excluded from that length.
Standard status and pairing completion use type `0x01` after the same reply code.
The independent verifier recomputes SHA-256 from the captured CVC bytes and
checks the fragment lengths, offsets, outcome, and hash. Diagnostic requests
send no commands to the credential.

[Trust recovery](trust-recovery.md) explains the ACU's validation, anchor-load,
restart, pairing, and PIN-verification decisions. The complete recovery sequence
is a control-flow example; the replay does not implement certificate enrollment
or a new end-to-end recovery transaction.

## PIN cache timing and error status

The `pin-expiration-*` cases show idle expiration, an armed request waiting
for presentation, expiration before VERIFY submission, expiration after
submission, and repeated successful verification without extending the
deadline. Every packet records elapsed time. Acquisition finishes at t=0;
the ten-second cache deadline is independent of completion delivery.

`pin-expiration-submitted` replays the existing contactless VERIFY exchange.
Its response delay is modeled; the source capture makes no timing claim.
The other timing cases model credential state and send no captured APDUs.
The verifier checks fixed completion sequences, timestamps, and final state.

`auto-status-word` splits a modeled credential failure status `6982` between
two OSDP 3.0 multipart replies. The verifier checks the entire reassembled
payload and rejects incomplete or invalid trailing status-word lengths.

SPE retain-cache and Auto Execute flags are now `0x01` and `0x02`.
PIV errors use consecutive assignments from `0x1020` through `0x1029`.

## Capture boundaries

OSDP messages are generated examples, not hardware OSDP captures. Card APDUs
are original captured data. Each APDU has a source index and purpose. The
replay retains intervening exchanges so its SM counters and MAC chains remain
valid. In particular, the contact capture includes provisioning-related
plaintext PIN and pairing-code retrieval before SM establishment; these are
capture context, not steps required by automatic card preparation. The
contactless cached-PIN example retains the capture's intervening reads and
authentication exchanges before PIN verification.

The proof covers the selected recorded sessions. It does not generate fresh
OPACITY sessions or claim that the captured card accepted a new command
sequence. The existing PIV Auto challenge/signature examples remain the proof
for challenge derivation. These captures cannot prove a new plaintext `0x9E`
Auto transaction by reusing a signature captured under SM.

The harness assumes OSDP Secure Channel authorization as a test-only
precondition. Production implementations still enforce the proposal's channel
requirements. Each example starts at sequence `0x01` on an established OSDP
link with PD address `0x01`; startup synchronization is outside the example.

## Files and provenance

`sm-credential-rejection` models an authenticated incorrect-PIN response.
The PD clears the failed cached PIN and PIN-verification status, preserves SM
and VCI, and reports the mismatch once. The credential's modeled `0x63C2`
contains a retry count; the one-byte SPE reply reports only the mismatch.
The ACU uses Mode `0x06` to query remaining attempts. The example does not
claim a captured failure response.

`examples.json` contains complete OSDP packets, exact replayed APDUs, source
references, and verification summaries. Source files and anchors remain in
`test-vectors/`; the generator does not modify them. Their single-use private
values and PINs are public test material.

The independent verifier's cryptographic equations follow the MIT-0
OpenPhysical `verify_vectors.py` supplied with the original SM/VCI capture
package. Trust parsing/signature validation uses this repository's existing
`validate_vci_chain.py`. The replay reuses the GET DATA simulator's OSDP framing.
