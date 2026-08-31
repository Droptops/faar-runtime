from __future__ import annotations

import hashlib
import json
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
