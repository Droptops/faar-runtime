from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any


# Financial canonical data should never need absurd decimal precision or exponent
# ranges. Bounding them prevents inputs such as Decimal("1e100000000") from
# turning canonical serialization into an allocation/CPU denial of service.
MAX_DECIMAL_DIGITS = 100
MAX_DECIMAL_ABS_EXPONENT = 100

# Monetary amounts supplied as strings must use a plain ASCII decimal grammar.
# Decimal() itself accepts surrounding whitespace, underscores, exponents, signs
# and any Unicode digit script; those forms would be forwarded verbatim to an
# adapter and admit unboundedly many encodings of one economic value.
MONEY_STRING_PATTERN = re.compile(r"\A(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?\Z", re.ASCII)


def _canonical_decimal(value: Decimal) -> str:
    if not value.is_finite():
        raise ValueError("non-finite Decimal cannot be canonicalized")
    sign, digits, exponent = value.as_tuple()
    if len(digits) > MAX_DECIMAL_DIGITS or abs(exponent) > MAX_DECIMAL_ABS_EXPONENT:
        raise ValueError("Decimal exceeds canonical precision/exponent bounds")
    adjusted = value.adjusted() if value != 0 else 0
    if abs(adjusted) > MAX_DECIMAL_ABS_EXPONENT:
        raise ValueError("Decimal magnitude exceeds canonical bounds")
    return format(value, "f")


def parse_bounded_decimal(raw: object) -> Decimal | None:
    """Parse an untrusted economic amount into a canonically bounded Decimal.

    Every component that reads an amount (gates, usage reservation, permit signer,
    settlement integrity, reference venues) must share this parser so the amount
    that is authorized, reserved, permitted and executed is one value. Returns
    None for anything that is not a finite, canonically serialisable amount:
    booleans, unsupported types, non-finite values, strings outside the plain
    decimal grammar, JSON numbers whose shortest form is outside that grammar
    (exponents, more than 8 fractional digits, binary artefacts such as
    ``0.30000000000000004``), and precisions/magnitudes beyond the canonical
    bounds (a 12-byte ``"1e-999999999"`` would otherwise make
    ``format(value, "f")`` allocate gigabytes).
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, str):
        if MONEY_STRING_PATTERN.fullmatch(raw) is None:
            return None
        value = Decimal(raw)
    elif isinstance(raw, int):
        # JSON integers take the string grammar (at most 18 integer digits) so a
        # number and its string form denote one bounded value.
        if raw.bit_length() > 256:
            return None
        if MONEY_STRING_PATTERN.fullmatch(str(raw).lstrip("-")) is None:
            return None
        value = Decimal(raw)
    elif isinstance(raw, float):
        if raw != raw or raw in (float("inf"), float("-inf")):
            return None
        # A JSON number is admitted only when its shortest round-trip form already
        # satisfies the string grammar: no exponent, at most 8 fractional digits.
        # 1e-9, 50.123456789 and 0.1 + 0.2 are rejected exactly as their string
        # forms are, so one economic value has one canonical amount.
        text = repr(raw)
        if MONEY_STRING_PATTERN.fullmatch(text.lstrip("-")) is None:
            return None
        value = Decimal(text)
    elif isinstance(raw, Decimal):
        # A plain copy: a Decimal subclass with overridden comparison or
        # formatting must not survive into gates, ledgers or evidence.
        value = Decimal(raw)
    else:
        return None
    if not value.is_finite():
        return None
    try:
        _canonical_decimal(value)
    except ValueError:
        return None
    return value


def _canonicalize(value: Any) -> Any:
    # Do not use dataclasses.asdict here. asdict deep-copies values and is not
    # compatible with read-only MappingProxyType values used by the security
    # model. Reading fields directly also makes the canonicalization boundary
    # explicit.
    if is_dataclass(value):
        return {f.name: _canonicalize(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return _canonical_decimal(value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("naive datetime cannot be canonicalized")
        return value.isoformat()
    # Sets are semantically unordered, so sort their canonical members. Tuples
    # are ordered and MUST retain order; treating both alike creates canonical
    # hash collisions for order-sensitive tuples.
    if isinstance(value, (set, frozenset)):
        return sorted((_canonicalize(v) for v in value), key=lambda x: json.dumps(x, sort_keys=True, allow_nan=False))
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    if isinstance(value, Mapping):
        keys = list(value.keys())
        if any(not isinstance(k, str) for k in keys):
            raise ValueError("canonical mapping keys must be strings")
        return {k: _canonicalize(value[k]) for k in sorted(keys)}
    if isinstance(value, float):
        # json.dumps would otherwise emit non-standard NaN/Infinity tokens.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite float cannot be canonicalized")
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
