# Contactless PIV Auto trust recovery

## Starting conditions

PIV Auto requests authentication with key `0x9A` over contactless. Credential
SM is enabled. The credential supports SM and VCI but requires a pairing code.
The PD trust store is empty. The ACU holds the authorized root certificates,
certificate-validation policy, and a way to obtain the pairing code.

This is a control-flow example. The packet replay covers SM, pairing, PIN
verification, and diagnostic encodings separately. The full recovery sequence
has not been captured from an OSDP implementation.

## Sequence

1. The credential is presented. PIV Auto terminates with `PIVSTATUS` Result
   `0x02`, Detail `0x01` (trust store empty). The PD sends no `0x9A`
   authentication command.
2. After receiving the complete result, the ACU requests `CARDSTATUS` type
   `0x02`. The diagnostic reports Outcome `0x02`, Detail `0x01`, and no CVC
   hash. SM setup was skipped because the trust store was empty.
3. The ACU requests `PIVGETDATA` for object `0x5FC122`, with Tag Length,
   Offset, and Requested Length all zero. The PD reads the credential through
   contactless and returns the complete signer object. If the read fails,
   the ACU selects another supported workflow or ends the transaction.
4. The ACU extracts signer certificate tag `0x70` and any intermediate CVC
   in tag `0x7F21`. The ACU validates the signer chain to an authorized root,
   validity, revocation, and the PIV/PIV-I content-signing extended key usage.
   Any intermediate CVC must satisfy the proposal's signature and linkage
   checks. An IIN match alone does not establish trust.
5. After validation, the ACU loads the signer's public key and certificate-
   derived IIN with `PIVVCILOADTA`. The ACU waits for successful completion.
6. The ACU reapplies the same `PIVMODE` configuration. This starts a new Auto
   attempt and clears the previous PIN and SM state. The PD establishes SM,
   then reports Result `0x05`, Detail `0x01` (pairing code required).
7. The ACU sends `PIVXMITPAIRING` and waits for `CARDSTATUSR` security status
   `0x01` (SM and VCI established).
8. The ACU sends `PIVSPE` Mode `0x01`, with Auto Execute clear, to collect
   and verify the PIN. The ACU waits for `PIVSPER` success.
9. The ACU reads the `0x9A` certificate using `PIVGETDATA` object `0x5FC105`,
   then sends a fresh `CRAUTH` challenge for key `0x9A`. The ACU validates
   the certificate and challenge response before deciding access.

The ACU proceeds only after a successful result at each step. Steps 7–9 are
commanded operations; PIV Auto has already reported its result. Reapplying
PIVMODE during those steps would clear the SM and PIN state. PIV Auto remains
configured for the next credential presentation.

## Other outcomes

- **SM unsupported:** Result `0x02`, Detail `0x05`. Loading an anchor cannot
  add SM capability. The ACU selects another supported workflow or ends the transaction.
- **VCI unsupported:** Result `0x05`, Detail `0x03`, once SM is established.
  The ACU selects another supported workflow or ends the transaction.
- **No matching trust path:** Result `0x02`, Detail `0x02`. The ACU may inspect
  the signer object and its authorized trust configuration. Recovery depends
  on the required data being accessible and valid.
- **Failed certificate or cryptogram check:** Result `0x02`, Detail `0x03`
  or `0x04`. The PD blocks credential operations. The diagnostic remains
  available for investigation; trust recovery does not bypass validation.

## Data access and diagnostics

Each PIVGETDATA request reads the credential through the active interface.
No workflow step relies on a PD object cache. Access denied over contactless
remains a failure; only the ACU can select an alternative workflow.

The credential's own SM CVC arrives during key establishment. The diagnostic
returns its SHA-256 hash when a complete CVC was received, even if validation
failed. The hash covers the received `0x7F21` tag, encoded length, and value.
The PD retains only the diagnostic record, with no requirement to retain the
CVC for later retrieval. GETDATA `0x5FC122` accesses the signer/intermediate
object, not the credential's own SM CVC.
