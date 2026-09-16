#!/usr/bin/env python3
"""Small deterministic PIVGETDATA/OSDP model; no hardware or Secure Channel."""

from dataclasses import dataclass
import struct

MAX_FRAME = 128
FRAGMENT_BYTES = 114


class PIVError(ValueError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def valid_tag(tag):
    """A complete one-to-three-octet BER tag, without padding."""
    if not 1 <= len(tag) <= 3 or tag[0] == 0 or tag == b"\xff":
        return False
    if tag[0] & 31 != 31:
        return len(tag) == 1
    return (len(tag) > 1 and tag[1] & 127 != 0
            and all(x & 128 for x in tag[1:-1]) and not tag[-1] & 128)


@dataclass(frozen=True)
class Request:
    object_id: bytes
    tag: bytes = b""
    offset: int = 0
    requested: int = 0

    def check_fields(self):
        """PD-side checks cover field sizes, not identifier or selector syntax."""
        if not 1 <= len(self.object_id) <= 3 or len(self.tag) > 3:
            raise PIVError(0x0005, "invalid identifier/tag length")
        if not 0 <= self.offset <= 65535 or not 0 <= self.requested <= 65535:
            raise PIVError(0x0005, "invalid range")

    def encode(self):
        self.check_fields()
        # The ACU validates the identifiers it supplies; the PD treats them as bytes.
        if not valid_tag(self.object_id) or (self.tag and not valid_tag(self.tag)):
            raise PIVError(0x0005, "invalid identifier/tag")
        return (b"\xa3" + bytes([len(self.object_id)]) + self.object_id
                + bytes([len(self.tag)]) + self.tag
                + struct.pack("<HH", self.offset, self.requested))

    @classmethod
    def decode(cls, data):
        try:
            if data[0] != 0xA3 or not 1 <= data[1] <= 3:
                raise ValueError
            end = 2 + data[1]
            count = data[end]
            if count > 3 or len(data) != end + 1 + count + 4:
                raise ValueError
            result = cls(data[2:end], data[end + 1:end + 1 + count],
                         *struct.unpack("<HH", data[-4:]))
            result.check_fields()
            return result
        except (IndexError, ValueError, struct.error) as exc:
            raise PIVError(0x0005, "malformed request") from exc


def tlv_at(data, start=0):
    """Return tag, value start, end; only definite lengths are accepted."""
    try:
        pos = start + 1
        if data[start] & 31 == 31:
            while data[pos] & 128:
                pos += 1
            pos += 1
        tag = data[start:pos]
        if tag[0] == 0 or (len(tag) > 1 and tag[1] & 127 == 0):
            raise ValueError
        size = data[pos]
        pos += 1
        if size & 128:
            count = size & 127
            if not 1 <= count <= 126 or pos + count > len(data):
                raise ValueError
            size = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        end = pos + size
        if end > len(data):
            raise ValueError
        return tag, pos, end
    except (IndexError, ValueError) as exc:
        raise PIVError(0x102A, "malformed BER-TLV") from exc


def select_response(request, response):
    """Select the whole response or one complete direct-child TLV, then apply the range."""
    request.check_fields()
    if not request.tag:
        selected = response
    elif not response:
        if request.tag:
            raise PIVError(0x1024, "missing child")
        selected = b""
    else:
        _, begin, end = tlv_at(response)
        if end != len(response):
            raise PIVError(0x102A, "trailing bytes")
        selected = response
        if request.tag:
            matches = []
            while begin < end:
                tag, value, stop = tlv_at(response, begin)
                if stop > end:
                    raise PIVError(0x102A, "child exceeds container")
                if tag == request.tag:
                    matches.append(response[begin:stop])
                begin = stop
            if not matches:
                raise PIVError(0x1024, "missing child")
            if len(matches) != 1:
                raise PIVError(0x1029, "ambiguous child")
            selected = matches[0]
    if request.offset > len(selected):
        raise PIVError(0x0005, "offset beyond selected data")
    remaining = len(selected) - request.offset
    count = remaining if request.requested == 0 else min(request.requested, remaining)
    if count > 65535:
        raise PIVError(0x102B, "selected transfer exceeds multipart capacity")
    return selected[request.offset:request.offset + count]


def crc16(data):
    crc = 0x1D0F
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 65535
    return crc


def frame(payload, sequence, reply=False, address=1):
    if not 0 <= sequence <= 3 or not 0 <= address <= 126:
        raise ValueError("invalid link field")
    packet = (bytes([0x53, address | (0x80 if reply else 0)])
              + struct.pack("<H", len(payload) + 7) + bytes([4 | sequence]) + payload)
    if len(packet) + 2 > MAX_FRAME:
        raise ValueError("frame too large")
    return packet + struct.pack("<H", crc16(packet))


def decode_frame(packet):
    if (len(packet) < 8 or len(packet) > MAX_FRAME or packet[0] != 0x53
            or int.from_bytes(packet[2:4], "little") != len(packet)
            or packet[4] & 0xFC != 4
            or crc16(packet[:-2]) != int.from_bytes(packet[-2:], "little")):
        raise ValueError("invalid CRC frame")
    return packet[1], packet[4] & 3, packet[5:-2]


class Peripheral:
    """One staged snapshot, with exact retransmission replay and explicit abort."""
    def __init__(self, objects=None, error=None, address=1, resource_limit=65535,
                 delay_polls=0, status_word=None):
        self.objects = objects or {}
        self.error = error
        self.address = address
        self.resource_limit = resource_limit
        self.delay_polls = delay_polls
        self.status_word = status_word
        self.pending = None
        self.position = 0
        self.previous = None
        self.previous_reply = None
        self.sequence = None

    def exchange(self, packet):
        address, sequence, payload = decode_frame(packet)
        if address != self.address:
            raise ValueError("not addressed to this PD")
        if sequence != 0 and packet == self.previous:
            return self.previous_reply
        expected = 1 if self.sequence in (None, 0, 3) else self.sequence + 1
        if sequence != 0 and sequence != expected:
            return frame(b"\x41\x04", sequence, True, self.address)
        if sequence == 0:
            self.pending = None
            self.position = 0
        if payload == b"\xa2":
            self.pending = None
            self.position = 0
            answer = b"\x40"
        elif payload == b"\x60":
            if self.pending is None:
                answer = b"\x40"
            elif self.delay_polls:
                self.delay_polls -= 1
                answer = b"\x40"
            elif isinstance(self.pending, int):
                answer = b"\x8a" + struct.pack("<H", self.pending)
                if self.status_word is not None:
                    answer += self.status_word.to_bytes(2, "big")
                self.pending = None
            else:
                chunk = self.pending[self.position:self.position + FRAGMENT_BYTES]
                answer = b"\x80" + struct.pack("<HHH", len(self.pending), self.position, len(chunk)) + chunk
                self.position += len(chunk)
                if self.position == len(self.pending):
                    self.pending = None
        elif self.pending is not None:
            answer = b"\x41\x09"  # Reject interleaving without destroying the snapshot.
        elif payload[0] == 0xA3:
            try:
                request = Request.decode(payload)
            except PIVError:
                self.pending = 0x0005
                self.position = 0
                answer = b"\x40"
            else:
                try:
                    if self.error is not None:
                        raise PIVError(self.error, "injected card failure")
                    if request.object_id not in self.objects:
                        raise PIVError(0x1024, "object absent")
                    selected = select_response(request, self.objects[request.object_id])
                    if len(selected) > self.resource_limit:
                        raise PIVError(0x1021, "staging resource limit")
                    self.pending = selected
                except PIVError as exc:
                    self.pending = exc.code
                self.position = 0
                answer = b"\x40"
        else:
            answer = b"\x41\x03"
        result = frame(answer, sequence, True, self.address)
        self.previous, self.previous_reply, self.sequence = packet, result, sequence
        return result


class Controller:
    """ACU-side polling/reassembly using only received wire messages."""
    def __init__(self, request, address=1):
        self.address = address
        self.sequence = 1
        payload = request.encode() if isinstance(request, Request) else request
        self.command = frame(payload, self.sequence, address=address)
        self.accepted = False
        self.done = False
        self.data = bytearray()
        self.total = None
        self.error = None
        self.status_word = None
        self.last_reply = None

    def receive(self, packet):
        address, sequence, payload = decode_frame(packet)
        if packet == self.last_reply:
            return  # Link retransmission must not append a fragment twice.
        if self.done or address != self.address | 0x80 or sequence != self.sequence:
            raise ValueError("unexpected reply")
        if not self.accepted:
            if payload != b"\x40":
                raise ValueError("request not accepted")
            self.accepted = True
        elif payload == b"\x40" and self.total is None:
            pass  # The card operation is still in progress.
        elif len(payload) in (3, 5) and payload[0] == 0x8A and self.total is None:
            self.error = int.from_bytes(payload[1:3], "little")
            if len(payload) == 5:
                self.status_word = int.from_bytes(payload[3:5], "big")
            self.done = True
        elif len(payload) >= 7 and payload[0] == 0x80:
            total, offset, count = struct.unpack("<HHH", payload[1:7])
            if (count != len(payload) - 7 or count > FRAGMENT_BYTES
                    or (self.total is not None and total != self.total)):
                raise ValueError("invalid multipart lengths")
            if self.total is not None and count == 0 and offset >= total and offset != len(self.data):
                self.done = True
                self.error = "multipart-terminated"
            else:
                if offset != len(self.data) or offset + count > total:
                    raise ValueError("noncontiguous multipart reply")
                if count == 0 and total != 0:
                    raise ValueError("non-progressing multipart reply")
                self.total = total
                self.data.extend(payload[7:])
                self.done = len(self.data) == total
        else:
            raise ValueError("unexpected reply kind")
        self.last_reply = packet
        if not self.done:
            self.sequence = self.sequence % 3 + 1
            self.command = frame(b"\x60", self.sequence, address=self.address)


def transcript(request, response, error=None, delay_polls=0, status_word=None):
    object_id = request.object_id if isinstance(request, Request) else b"\x7e"
    pd = Peripheral({object_id: response}, error=error,
                    delay_polls=delay_polls, status_word=status_word)
    acu = Controller(request)
    rows = []
    while not acu.done:
        if len(rows) > 1024:
            raise TimeoutError("simulation poll budget exhausted")
        command = acu.command
        reply = pd.exchange(command)
        rows.append({"command_hex": command.hex().upper(), "reply_hex": reply.hex().upper()})
        acu.receive(reply)
    return rows
