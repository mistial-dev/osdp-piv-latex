"""Bounded PIVSELECT model for payload and context tests, not a device driver."""
from dataclasses import dataclass

PIV_AID = bytes.fromhex("A000000308000010000100")
TWIC_PREFIX = bytes.fromhex("A00000036720000001")


class SelectionError(ValueError):
    def __init__(self, message, code=0x0005):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Request:
    model: int
    aid: bytes

    @classmethod
    def decode(cls, payload, supported_models=(1, 2, 3)):
        if len(payload) < 4 or payload[0] != 0xB0 or payload[1] != 0:
            raise SelectionError("invalid PIVSELECT header or flags")
        model, size = payload[2:4]
        if model not in (1, 2, 3) and not 0x80 <= model <= 0xFF:
            raise SelectionError("invalid Data Model")
        if model not in supported_models:
            raise SelectionError("unsupported Data Model")
        if not 5 <= size <= 16 or len(payload) != 4 + size:
            raise SelectionError("invalid AID length")
        return cls(model, bytes(payload[4:]))


class Peripheral:
    """Model only validation and atomic selection; credential outcomes are injected."""
    def __init__(self, supported_models=(1, 2, 3)):
        self.supported_models = supported_models
        self.model = None
        self.aid = b""
        self.security = {}
        self.interface = "contact"
        self.mode_flags = 0
        self.credential_calls = 0

    def select(self, payload, credential_select):
        request = Request.decode(payload, self.supported_models)
        self.credential_calls += 1
        # The callback supplies a parsed FCI AID, or None if tag 4F is absent.
        selected = credential_select(request.aid)
        aid = bytes(selected) if selected is not None else request.aid
        if (self.model, self.aid) != (request.model, aid):
            # Preserve a PIN collected before the first PIV presentation.
            first_piv = self.model is None and not self.aid and request.model == 1
            pin = self.security.get("cached_pin") if first_piv else None
            self.security.clear()
            if pin is not None:
                self.security["cached_pin"] = pin
        self.model, self.aid = request.model, aid
        return b"\x40"
