# PIVGETDATA worked exchanges

These deterministic simulator exchanges exercise the
proposed Enhanced PIV request and OSDP 3.0 PIVGETDATAR multi-part delivery, retaining the
OSDP 2.2 multi-part format.
The certificate, CHUID, Discovery and Key History response data come from the existing
repository card captures. Their source files are unchanged. `manifest.json` records each
source SHA-256, JSON field path, and explicit byte slice used for the fixed expected output.
Other cases are individually marked synthetic, including the empty BIT Group and TWIC
e-sticker. The synthetic error injection models card-operation outcomes.

From the repository root:

```sh
python3 scripts/generate_pivdata_examples.py
python3 scripts/check_pivdata_examples.py
python3 -m unittest discover -s scripts/tests -p 'test_pivdata.py' -v
```

`examples.json` is generated from the committed manifest. The generator never updates
expected outputs. The independent checker imports no simulator code: it uses Python's
`binascii.crc_hqx`, checks source hashes and explicit source slices, and validates the
transcript against the fixed expected bytes/errors. Unit tests also check two literal CRC
frames from OSDP 2.2 Annex E. The manifest is the reviewed oracle; changes to it require
review against the specification and source data.

Every exchange contains complete hexadecimal frames from SOM through CRC, without a
physical-layer mark byte. Address is 1; replies have the direction bit set. CRC control bit
is set, sequences cycle 1, 2, 3, 1, and CRC uses initial register 0x1D0F and polynomial
0x1021. Frames are at most 128 bytes. A PIVGETDATAR frame holds at most 114 data bytes:
5 header + 1 reply code + 6 multipart fields + 114 data + 2 CRC = 128.
Multipart fields are exactly the OSDP 2.2 uint16 little-endian total/offset/fragment-size
tuple, immediately after reply code 0x80. Reply offsets start at zero within the requested
data, independently of the command's Offset. Only data bytes are divided across replies;
each reply repeats the reply code and multi-part fields. TLV headers appear once in the
reassembled data. A fragment boundary may split a tag, length, or value.

The request is A3, identifier length, identifier, element-tag length, optional tag,
offset (uint16 little-endian), and requested length (uint16 little-endian). Tag length
zero selects the unchanged complete card response, including its outer tag, length, and
value. A nonzero selector selects the unique direct child, including its original tag,
length, and value, but not the enclosing object's header. Offset and Requested Length
then identify the bytes to return from that selection. No recursive search, certificate
decompression, re-encoding, wrapper substitution or padding occurs. Requested Length
clips at the end of the selected data; zero means all remaining bytes. Empty success is
a zero-total/zero-offset/zero-size PIVGETDATAR. An element with an empty value still returns
its tag and length unless the requested range excludes them.

The CHUID examples show both complete elements and fixed-length values. Tag 30 has
a one-byte tag and one-byte length: Offset 2 and Requested Length 25 return only the
FASC-N. Tag 34 uses the same header size: Offset 2 and Requested Length 16 return only
the UUID. These requests exclude later CHUID elements. Certificate tag 70 uses a
four-byte header in these captures; its complete selected TLV includes that header and
does not include the enclosing tag 53 or sibling elements.

The ACU and PD models are separate. The ACU advances by received frames, never by
inspecting PD state. The PD accepts with ACK and returns results only on later POLLs;
processing delays return ACK. PIVERROR (0x8A) is terminal before any data fragment and
may include SW1/SW2. The PD stages a snapshot and rejects competing commands with
NAK 0x09 without losing it. ABORT discards pending output. Link retransmissions replay
the same response; sequence zero restarts link/operation state. The ACU checks total,
contiguity, duplicate replies and early multipart termination.

These examples omit OSDP Secure Channel for clarity. Deployed implementations must
meet the profile's Secure Channel requirements. Card-side GET DATA, APDU chaining,
secure-messaging verification, certificate validation, and hardware timing
remain separate integration and conformance checks.

The oracle fixtures cover real uncompressed and gzip-compressed certificate values;
compressed bytes remain compressed. Tests cover the 65,535-byte multipart limit and
bounded ranges within larger objects.
