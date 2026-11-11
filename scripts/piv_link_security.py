"""Reference authorization policy for sensitive ACU--PD operations."""
from dataclasses import dataclass, field

# Container identifiers and card tags, interpreted in the selected data model.
PIV_PRIVATE_OBJECTS = frozenset([0x6010, 0x6030, 0x1015, 0x5FC103, 0x5FC108, 0x5FC121])
TWIC_PRIVATE_OBJECTS = frozenset([
    0x6011, 0x6012, 0x2001, 0x2003, 0x6030, 0x3001, 0x1015,
    0xDFC001, 0xDFC002, 0xDFC101, 0xDFC103, 0xDFC108, 0xDFC109, 0xDFC121,
])


class ChannelRequired(ValueError):
    code = 0x0006


def protected_operation(command: int, model: int = 1, object_id: bytes = b"") -> bool:
    if command in (0xAC, 0xAB, 0x87):  # LOADTPK, BIOMATCH, BIOMATCHR
        return True
    if command not in (0xA3, 0x80):  # GETDATA / its data reply, with request context
        return False
    private = TWIC_PRIVATE_OBJECTS if model == 2 else PIV_PRIVATE_OBJECTS
    return int.from_bytes(object_id, "big") in private


@dataclass(frozen=True)
class Channel:
    session: object | None = None
    version: str = ""
    deployment_keys: bool = False

    def require(self, protected_message: bool) -> None:
        if (self.session is None or self.version != "3.0"
                or not self.deployment_keys or not protected_message):
            raise ChannelRequired("Secure Channel 3.0 with deployment-specific keys required")


@dataclass
class ProtectedTransfer:
    """Keep payload and replay state bound to one authenticated session."""
    session: object
    tpk: bytearray = field(default_factory=bytearray)
    pending: bytearray = field(default_factory=bytearray)
    replay: bytes = b""
    active: bool = True

    @classmethod
    def begin(cls, channel: Channel, protected_message: bool):
        channel.require(protected_message)
        return cls(channel.session)

    def release(self, channel: Channel, protected_message: bool, count: int) -> bytes:
        if count < 0:
            raise ValueError("invalid fragment length")
        if not self.active:
            raise ChannelRequired("fresh protected request required")
        if channel.session != self.session:
            self.cancel()
            raise ChannelRequired("protected session ended")
        try:
            channel.require(protected_message)
        except ChannelRequired:
            self.cancel()
            raise
        result = bytes(self.pending[:count])
        del self.pending[:count]
        self.replay = result
        return result

    def cancel(self) -> None:
        self.tpk[:] = bytes(len(self.tpk))
        self.pending[:] = bytes(len(self.pending))
        self.tpk.clear()
        self.pending.clear()
        self.replay = b""
        self.active = False
