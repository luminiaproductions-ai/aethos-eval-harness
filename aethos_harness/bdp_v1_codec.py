"""BDP-v1 (Bushido Dense Protocol v1) Telepathy Wire encoder, decoder, and token profiler."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Mapping, Sequence, Tuple, Union

VALID_HEADERS = ("BDP:v1", "BDP:VERIFY")
CANONICAL_REQUIRED_KEYS = ("INTENT", "DOM", "TGT", "REQ", "GATE")
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+|[^\sA-Za-z0-9]")
_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True)
class BDPFrame:
    """Decoded structured representation of a BDP-v1 wire packet."""

    header: str
    fields: Dict[str, str]
    raw: str

    @property
    def intent(self) -> str:
        return self.fields.get("INTENT", "")

    @property
    def dom(self) -> str:
        return self.fields.get("DOM", "")

    @property
    def tgt(self) -> str:
        return self.fields.get("TGT", "")

    @property
    def req(self) -> str:
        return self.fields.get("REQ", "")

    @property
    def gate(self) -> str:
        return self.fields.get("GATE", "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "fields": dict(self.fields),
            "raw": self.raw,
        }


def _sanitize_value(value: str) -> str:
    """Normalize a BDP field value so delimiters cannot break framing."""
    cleaned = str(value).strip().replace("\r", " ").replace("\n", " ")
    cleaned = cleaned.replace("|", "/")
    cleaned = re.sub(r"\s+", "_", cleaned)
    if not cleaned:
        raise ValueError("BDP field value must not be empty.")
    return cleaned


def _format_req(req: Union[str, Sequence[str]]) -> str:
    if isinstance(req, str):
        return _sanitize_value(req)
    parts = [_sanitize_value(item) for item in req if str(item).strip()]
    if not parts:
        raise ValueError("BDP REQ sequence must contain at least one constraint.")
    return "+".join(parts)


def encode_bdp(
    intent: str,
    dom: str,
    tgt: str,
    req: Union[str, Sequence[str]],
    gate: str,
    *,
    header: str = "BDP:v1",
    extra: Mapping[str, str] | None = None,
    sep: str = "=",
) -> str:
    """Encode structured engineering parameters into a compact BDP-v1 wire frame.

    Canonical output format:
        ``BDP:v1|INTENT=<intent>|DOM=<dom>|TGT=<tgt>|REQ=<req>|GATE=<gate>``
    """
    if header not in VALID_HEADERS:
        raise ValueError(f"Unsupported BDP header {header!r}; expected one of {VALID_HEADERS}.")
    if sep not in ("=", ":"):
        raise ValueError(f"Unsupported key-value separator {sep!r}; expected '=' or ':'.")

    ordered: Dict[str, str] = {
        "INTENT": _sanitize_value(intent),
        "DOM": _sanitize_value(dom),
        "TGT": _sanitize_value(tgt),
        "REQ": _format_req(req),
        "GATE": _sanitize_value(gate),
    }

    if extra:
        for raw_key, raw_val in extra.items():
            key = str(raw_key).strip().upper()
            if not _KEY_RE.match(key):
                raise ValueError(f"Invalid BDP field key: {raw_key!r}")
            if key in ordered:
                raise ValueError(f"Duplicate BDP field key: {key!r}")
            ordered[key] = _sanitize_value(raw_val)

    segments = [header] + [f"{k}{sep}{v}" for k, v in ordered.items()]
    return "|".join(segments)


def _split_kv(segment: str) -> Tuple[str, str]:
    """Split a BDP segment on the earliest '=' or ':' key-value delimiter."""
    eq_idx = segment.find("=")
    colon_idx = segment.find(":")
    candidates = [idx for idx in (eq_idx, colon_idx) if idx != -1]
    if not candidates:
        raise ValueError(f"Malformed BDP segment (missing '=' or ':'): {segment!r}")
    idx = min(candidates)
    key = segment[:idx].strip().upper()
    val = segment[idx + 1 :].strip()
    if not _KEY_RE.match(key):
        raise ValueError(f"Invalid BDP field key {key!r} in segment {segment!r}")
    if not val:
        raise ValueError(f"Empty value for BDP field {key!r}")
    return key, val


def decode_bdp(frame: str) -> BDPFrame:
    """Decode a BDP-v1 or BDP:VERIFY wire string into a structured ``BDPFrame``.

    Accepts both canonical ``KEY=VALUE`` packets and legacy ``KEY:VALUE`` packets.
    """
    if not isinstance(frame, str) or not frame.strip():
        raise ValueError("BDP frame must be a non-empty string.")
    raw = frame.strip()
    parts = raw.split("|")
    header = parts[0].strip()
    if header not in VALID_HEADERS:
        raise ValueError(f"Invalid BDP header {header!r}; expected one of {VALID_HEADERS}.")
    if len(parts) < 2:
        raise ValueError("BDP frame contains no key-value fields.")

    fields: Dict[str, str] = {}
    for segment in parts[1:]:
        key, val = _split_kv(segment)
        if key in fields:
            raise ValueError(f"Duplicate BDP field {key!r} in frame.")
        fields[key] = val

    return BDPFrame(header=header, fields=fields, raw=raw)


def validate_bdp_frame(
    frame: Union[str, BDPFrame],
    required_keys: Sequence[str] = CANONICAL_REQUIRED_KEYS,
) -> Tuple[bool, List[str]]:
    """Validate syntax and required keys of a BDP-v1 wire packet."""
    errors: List[str] = []
    if isinstance(frame, str):
        try:
            parsed = decode_bdp(frame)
        except ValueError as exc:
            return False, [str(exc)]
    else:
        parsed = frame

    for req_key in required_keys:
        if req_key not in parsed.fields or not parsed.fields[req_key]:
            errors.append(f"Missing required BDP field: {req_key}")

    return len(errors) == 0, errors


def estimate_tokens(text: str) -> int:
    """Deterministic subword-like token count estimator for prose and BDP packets."""
    if not text:
        return 0
    return len(_TOKEN_RE.findall(text))


def compression_stats(prose_text: str, bdp_frame: str) -> Dict[str, Any]:
    """Measure deterministic token compression between verbose prose and BDP-v1."""
    decode_bdp(bdp_frame)
    prose_tokens = estimate_tokens(prose_text)
    bdp_tokens = estimate_tokens(bdp_frame)
    if prose_tokens <= 0:
        raise ValueError("prose_text must contain at least one token.")
    reduction_pct = round((1.0 - (bdp_tokens / prose_tokens)) * 100.0, 2)
    ratio = round(prose_tokens / max(1, bdp_tokens), 2)
    return {
        "prose_tokens": prose_tokens,
        "bdp_tokens": bdp_tokens,
        "reduction_pct": reduction_pct,
        "compression_ratio": ratio,
    }
