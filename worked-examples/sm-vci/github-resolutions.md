# GitHub issue coverage

These notes describe the proposal changes after checkpoint `b00ab36`.
They are local review notes; no issue has been closed or commented on.

All eight repository issues, including comments, were rechecked on 2026-09-16.
The five open issues are 3, 4, 5, 6, and 11; each is covered below. Closed
issues 1, 2, and 7 were also checked for regressions.

## Issue 1: Build requirements (closed)

https://github.com/mistial-dev/osdp-piv-latex/issues/1

README documents XeLaTeX and latexmk setup. Carlito and its OFL license are
vendored under fonts. The current proposal builds successfully with those fonts.

## Issue 2: Command naming (closed)

https://github.com/mistial-dev/osdp-piv-latex/issues/2

The active proposal uses PIVLOADTPK, PIVXMITPAIRING, PIVVCILOADTA, and
PIVVCITASTATUS without an extra separator after PIV. GET DATA uses the same
convention: PIVGETDATA and PIVGETDATAR.

## Issue 3: VCI and cached-PIN verification

https://github.com/mistial-dev/osdp-piv-latex/issues/3

SM setup, VCI pairing, and cardholder PIN verification are separate steps.
Mode `0x02` submits the cached PIN over established VCI. Mode `0x03` uses
the selected interface, with SM when established. An accepted commanded
request initiates verification; Auto Execute waits for presentation and makes
one attempt. Pairing-required results end that attempt so the ACU can supply
the pairing code. See the commanded workflow and error-recovery diagrams.

## Issue 4: Cached PIN reuse

https://github.com/mistial-dev/osdp-piv-latex/issues/4

Successful verification preserves the cached PIN until its original deadline
or another defined clearing event. It does not restart the timer. The ACU
can request another verification while the cache remains valid. Loss of SM
clears the cache. A PIN mismatch also clears the cache, while preserving
SM and established pairing/VCI.
The `pin-expiration-reuse` example demonstrates two explicit verifications
followed by expiration at the original deadline.

## Issue 5: Default timeout bounds

https://github.com/mistial-dev/osdp-piv-latex/issues/5

Start and inter-key defaults must each be documented and within 1–255
seconds. An explicit nonzero ACU value overrides the corresponding default.
Deployment and conformance tests can use explicit values for repeatable timing.
The proposal does not impose one default on every installation.

## Issue 6: Expiration notification

https://github.com/mistial-dev/osdp-piv-latex/issues/6

Idle expiration silently erases the cache. Mode `0x00` reports cache
availability independently from credential PIN verification. A cached-PIN
request whose cache has expired ends with `0x0A` (no cached PIN).
Expiration while an accepted Auto Execute request waits for presentation
produces that request's terminal PIVSPER on a poll.

The final validity check is immediately before VERIFY submission. At the
deadline, expiration wins. After submission, the exchange finishes and reports
its actual result. Five timing examples and the cache-lifecycle diagram cover
these boundaries. Captured VERIFY data and modeled timing are labeled separately.

## Issue 11: Numbering

https://github.com/mistial-dev/osdp-piv-latex/issues/11

SPE flags now use `0x01` (retain across removal) and `0x02` (Auto Execute).
The PIV-specific errors are consecutive from `0x1020` through `0x1029`:
credential removal is `0x1026`, ambiguous selection `0x1027`, malformed
object encoding `0x1028`, and excessive transfer length `0x1029`.
Affected GET DATA oracles, generated packets, CRCs, tests, and tables were
updated together. Historical changelog entries preserve the earlier decisions.

## Issue 7: Multipart framing

https://github.com/mistial-dev/osdp-piv-latex/issues/7

OSDP 3.0 total, offset, and fragment-size fields precede the logical record.
CARDSTATUSR has one explicit exception to placement immediately after CMND:
the user-approved Status Type discriminator precedes the multipart header
in every diagnostic fragment. The type byte is excluded from the logical
record and its lengths. Standard status and pairing completion carry Type
0x01; diagnostics carry Type 0x02. The other multipart layouts, including
PIVMODE and LOADTA raised in issue 7, retain their existing field order.
PIVSTATUS's appended
SW1/SW2 are part of that record. The `auto-status-word` example places SW1
and SW2 in separate fragments and verifies complete reassembly.
