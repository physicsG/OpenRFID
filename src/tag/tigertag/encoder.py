"""Official-SDK adapter for unsigned TigerTag Maker payloads.

The public functions in this module intentionally retain the field names used
by OpenRFID's original encoder while delegating the protocol model and binary
serialization to the official tigertag package. New user-written tags are
always canonical 80-byte Maker payloads occupying NTAG pages 4 through 23.
"""

from __future__ import annotations

import math
import threading
from copy import deepcopy
from datetime import date, datetime, timezone
from typing import Any

from tigertag import (
    ID_TIGERTAG,
    MAKER_PRODUCT_ID,
    TigerTag,
    TigerTagDB,
    __version__ as TIGERTAG_SDK_VERSION,
)


USER_DATA_START_PAGE = 4
USER_DATA_END_PAGE = 23
PAYLOAD_LENGTH_BYTES = 80
PAYLOAD_PAGE_COUNT = PAYLOAD_LENGTH_BYTES // 4

TIGERTAG_TAG_ID = ID_TIGERTAG
TIGERTAG_MAKER_PRODUCT_ID = MAKER_PRODUCT_ID
TIGERTAG_SDK_COMMIT = "f3e2e2e8a1fdf88f91fb43ca4b5c5fbfb88f81af"

_TIGERTAG_EPOCH = datetime(2000, 1, 1, tzinfo=timezone.utc)
_DB: TigerTagDB | None = None
_DB_LOCK = threading.Lock()

_DB_TABLES = {
    "material": "_materials",
    "aspect": "_aspects",
    "type": "_types",
    "diameter": "_diameters",
    "brand": "_brands",
    "unit": "_units",
}
_ID_MAXIMUMS = {
    "material": 0xFFFF,
    "brand": 0xFFFF,
    "aspect": 0xFF,
    "type": 0xFF,
    "diameter": 0xFF,
    "unit": 0xFF,
}


def _database() -> TigerTagDB:
    global _DB
    with _DB_LOCK:
        if _DB is None:
            _DB = TigerTagDB()
        return _DB


def _option_records(kind: str, metadata_keys: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """Return a detached, deterministic, JSON-safe view of one SDK table."""
    records = getattr(_database(), _DB_TABLES[kind])
    options: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict) or record.get("id") is None:
            continue
        option: dict[str, Any] = {
            "id": int(record["id"]),
            "label": str(TigerTagDB.label(record)),
        }
        for key in metadata_keys:
            if key in record:
                option[key] = deepcopy(record[key])
        options.append(option)
    return sorted(options, key=lambda option: (option["label"].casefold(), option["id"]))


def get_options() -> dict[str, Any]:
    """Return official SDK registry choices for a TigerTag authoring form.

    The result is safe to serialize directly as JSON and does not expose the
    SDK's mutable internal database lists. Material recommendations are
    database enrichment for form defaults only; they are not claimed as fields
    currently present on a scanned tag.
    """
    return {
        "schema_version": 1,
        "sdk": {
            "name": "tigertag",
            "version": TIGERTAG_SDK_VERSION,
            "commit": TIGERTAG_SDK_COMMIT,
        },
        "materials": _option_records(
            "material",
            (
                "material_type",
                "filled_type",
                "density",
                "filled",
                "product_type_id",
                "recommended",
                "metadata",
            ),
        ),
        "brands": _option_records("brand"),
        "aspects": _option_records("aspect", ("color_count",)),
        "types": _option_records("type"),
        "diameters": _option_records("diameter"),
        "units": _option_records("unit", ("type",)),
    }


def _first(spec: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in spec and spec[key] is not None and spec[key] != "":
            return spec[key]
    return default


def _bounded_int(
    name: str,
    value: Any,
    *,
    minimum: int = 0,
    maximum: int,
    default: int = 0,
) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not math.isfinite(numeric) or not numeric.is_integer():
        raise ValueError(f"{name} must be an integer")
    result = int(numeric)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return result


def _resolve_id(kind: str, value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValueError(f"{kind} must be a label or numeric ID")
    if isinstance(value, (int, float)):
        return _bounded_int(kind, value, maximum=_ID_MAXIMUMS[kind])
    if not isinstance(value, str):
        raise ValueError(f"{kind} must be a label or numeric ID")

    text = value.strip()
    if not text:
        return default
    try:
        numeric_id = int(text, 0)
    except ValueError:
        try:
            numeric_id = int(text, 10)
        except ValueError:
            numeric_id = None
    if numeric_id is not None:
        return _bounded_int(kind, numeric_id, maximum=_ID_MAXIMUMS[kind])

    records = getattr(_database(), _DB_TABLES[kind])
    wanted = text.casefold()
    for record in records:
        labels = (
            record.get("label"),
            record.get("name"),
            record.get("title"),
            record.get("symbol"),
            record.get("value"),
        )
        if any(str(label).strip().casefold() == wanted for label in labels if label is not None):
            return _bounded_int(kind, record.get("id"), maximum=_ID_MAXIMUMS[kind])

    raise ValueError(f"Unknown TigerTag {kind}: {value!r}")


def _parse_color(value: Any, *, primary: bool) -> tuple[int, int, int, int]:
    default_alpha = 0xFF if primary else 0
    if value is None or value == "":
        return (0, 0, 0, default_alpha)

    if isinstance(value, bool):
        raise ValueError("color must be #RRGGBB, #RRGGBBAA, ARGB, or RGB(A) channels")

    if isinstance(value, int):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError("integer color must fit in 32 bits")
        if value <= 0xFFFFFF:
            return ((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF, default_alpha)
        # GenericFilament's integer representation is AARRGGBB.
        return ((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF, (value >> 24) & 0xFF)

    if isinstance(value, str):
        text = value.strip().lstrip("#")
        if len(text) not in (6, 8):
            raise ValueError("hex color must contain 6 RGB or 8 RGBA digits")
        try:
            channels = tuple(int(text[offset:offset + 2], 16) for offset in range(0, len(text), 2))
        except ValueError as exc:
            raise ValueError("hex color contains non-hexadecimal characters") from exc
        if len(channels) == 3:
            return (*channels, default_alpha)
        return channels

    if isinstance(value, (list, tuple)) and len(value) in (3, 4):
        channels = tuple(
            _bounded_int("color channel", channel, maximum=0xFF)
            for channel in value
        )
        if len(channels) == 3:
            return (*channels, default_alpha)
        return channels

    raise ValueError("color must be #RRGGBB, #RRGGBBAA, ARGB, or RGB(A) channels")


def _color_sources(spec: dict[str, Any]) -> tuple[Any, Any, Any]:
    sources: list[Any] = []
    colors = spec.get("colors")
    if isinstance(colors, (list, tuple)) and colors:
        if (
            len(colors) in (3, 4)
            and all(isinstance(value, (int, float)) for value in colors)
            and all(0 <= float(value) <= 0xFF for value in colors)
        ):
            sources.append(colors)
        else:
            sources.extend(colors[:3])

    while len(sources) < 3:
        index = len(sources) + 1
        aliases = {
            1: ("color_1", "color1", "color"),
            2: ("color_2", "color2", "secondary_color"),
            3: ("color_3", "color3", "tertiary_color"),
        }[index]
        sources.append(_first(spec, *aliases))

    return sources[0], sources[1], sources[2]


def _timestamp_from_spec(spec: dict[str, Any]) -> int | None:
    raw_timestamp = _first(spec, "timestamp")
    if raw_timestamp is not None:
        return _bounded_int("timestamp", raw_timestamp, maximum=0xFFFFFFFF)

    value = _first(spec, "manufacturing_date", "mfg_date")
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("manufacturing_date must be an ISO date or TigerTag timestamp")
    if isinstance(value, (int, float)):
        return _bounded_int("manufacturing_date", value, maximum=0xFFFFFFFF)

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError("manufacturing_date must be an ISO-8601 date or datetime") from exc
    else:
        raise ValueError("manufacturing_date must be an ISO date or TigerTag timestamp")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = int((parsed.astimezone(timezone.utc) - _TIGERTAG_EPOCH).total_seconds())
    return _bounded_int("manufacturing_date", seconds, maximum=0xFFFFFFFF)


def _uid_from_spec(spec: dict[str, Any]) -> bytes | None:
    value = _first(spec, "uid", "expected_uid")
    if value is None:
        return None
    if isinstance(value, str):
        text = value.replace(":", "").replace("-", "").replace(" ", "")
        try:
            value = bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError("uid must be a 7-byte hex string") from exc
    if not isinstance(value, (bytes, bytearray)) or len(value) != 7:
        raise ValueError("uid must contain exactly 7 bytes")
    return bytes(value)


def _message_from_spec(spec: dict[str, Any]) -> str:
    value = _first(spec, "message", "custom_message", default="")
    message = str(value or "")
    if len(message.encode("utf-8")) > 28:
        raise ValueError("message must be at most 28 UTF-8 bytes")
    return message


def _td_raw_from_spec(spec: dict[str, Any]) -> int:
    td_mm = _first(spec, "td_mm", "td_value")
    if td_mm is not None:
        try:
            numeric = float(td_mm)
        except (TypeError, ValueError) as exc:
            raise ValueError("td_mm must be a number") from exc
        if not math.isfinite(numeric):
            raise ValueError("td_mm must be a finite number")
        raw = int(round(numeric * 10))
    else:
        # Compatibility: the original encoder treated td as the raw u16.
        raw = _bounded_int("td", _first(spec, "td"), maximum=0xFFFF)

    if raw != 0 and not 10 <= raw <= 1000:
        raise ValueError("TigerTag TD must be 0 (undefined) or between 1.0 and 100.0 mm")
    return raw


def build_maker_tag(spec: dict[str, Any] | None) -> TigerTag:
    """Build and validate an unsigned TigerTag Maker model from an API spec."""
    if spec is None:
        spec = {}
    if not isinstance(spec, dict):
        raise ValueError("TigerTag spec must be an object")

    requested_product = _first(spec, "product_id", "id_product")
    if requested_product is not None:
        product_id = _bounded_int("product_id", requested_product, maximum=0xFFFFFFFF)
        # The old custom encoder used zero by default. Treat that legacy value
        # as a Maker request, but never fabricate a TigerTag+ cloud identity.
        if product_id not in (0, MAKER_PRODUCT_ID):
            raise ValueError("OpenRFID can only encode unsigned TigerTag Maker tags")

    color1, color2, color3 = _color_sources(spec)
    c1 = _parse_color(color1, primary=True)
    c2 = _parse_color(color2, primary=False)
    c3 = _parse_color(color3, primary=False)

    measure = _bounded_int(
        "measure",
        _first(spec, "measure", "weight_g"),
        maximum=0xFFFFFF,
    )
    available = _bounded_int(
        "measure_available",
        _first(spec, "measure_available", "available_quantity", default=measure),
        maximum=0xFFFFFF,
    )

    tag = TigerTag.create(
        product_id=MAKER_PRODUCT_ID,
        uid=_uid_from_spec(spec),
        id_material=_resolve_id("material", _first(spec, "id_material", "material")),
        id_aspect_1=_resolve_id("aspect", _first(spec, "id_aspect_1", "id_aspect1", "aspect_1")),
        id_aspect_2=_resolve_id("aspect", _first(spec, "id_aspect_2", "id_aspect2", "aspect_2")),
        id_type=_resolve_id("type", _first(spec, "id_type", "type")),
        id_diameter=_resolve_id("diameter", _first(spec, "id_diameter", "diameter")),
        id_brand=_resolve_id("brand", _first(spec, "id_brand", "brand")),
        color1_r=c1[0],
        color1_g=c1[1],
        color1_b=c1[2],
        color1_a=c1[3],
        color2_r=c2[0],
        color2_g=c2[1],
        color2_b=c2[2],
        color3_r=c3[0],
        color3_g=c3[1],
        color3_b=c3[2],
        measure=measure,
        id_unit=_resolve_id("unit", _first(spec, "id_unit", "unit")),
        nozzle_temp_min=_bounded_int(
            "temp_min_c", _first(spec, "nozzle_temp_min", "temp_min_c"), maximum=0xFFFF
        ),
        nozzle_temp_max=_bounded_int(
            "temp_max_c", _first(spec, "nozzle_temp_max", "temp_max_c"), maximum=0xFFFF
        ),
        dry_temp=_bounded_int(
            "dry_temp_c", _first(spec, "dry_temp", "dry_temp_c"), maximum=0xFF
        ),
        dry_time=_bounded_int(
            "dry_time_h", _first(spec, "dry_time", "dry_time_h"), maximum=0xFF
        ),
        bed_temp_min=_bounded_int(
            "bed_temp_min_c", _first(spec, "bed_temp_min", "bed_temp_min_c"), maximum=0xFF
        ),
        bed_temp_max=_bounded_int(
            "bed_temp_max_c", _first(spec, "bed_temp_max", "bed_temp_max_c"), maximum=0xFF
        ),
        timestamp=_timestamp_from_spec(spec),
        custom_message=_message_from_spec(spec),
        td_raw=_td_raw_from_spec(spec),
    )

    if available != measure:
        tag = tag.patch(measure_available=available)

    warnings = tag.validate()
    if warnings:
        raise ValueError("; ".join(warnings))
    return tag


def encode(spec: dict[str, Any] | None) -> bytes:
    """Encode a canonical 80-byte unsigned TigerTag Maker payload."""
    payload = build_maker_tag(spec).to_bytes()
    validate_maker_payload(payload)
    return payload


def erase() -> bytes:
    """Return exactly the TigerTag-owned 80 bytes cleared to zero."""
    payload = TigerTag.erase()
    if len(payload) != PAYLOAD_LENGTH_BYTES:
        raise RuntimeError("TigerTag SDK returned an unexpected erase payload length")
    return payload


def encode_blank() -> bytes:
    """Backward-compatible alias for erase."""
    return erase()


def decode_payload(payload: bytes, uid: bytes | None = None) -> TigerTag:
    """Decode an 80-byte Maker body or 144-byte signed TigerTag payload."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("TigerTag payload must be bytes")
    data = bytes(payload)
    if len(data) not in (PAYLOAD_LENGTH_BYTES, 144):
        raise ValueError("TigerTag payload must be exactly 80 or 144 bytes")
    if uid is None:
        return TigerTag.from_dump(data)
    if not isinstance(uid, (bytes, bytearray)) or len(uid) != 7:
        raise ValueError("TigerTag UID must contain exactly 7 bytes")
    return TigerTag.from_pages(bytes(uid), data)


def validate_maker_payload(payload: bytes, uid: bytes | None = None) -> TigerTag:
    """Validate an exact unsigned Maker body and return its SDK model.

    This is suitable for controller-side request validation and read-back
    verification. It deliberately rejects TigerTag+, Init, signatures, length
    drift, and SDK field warnings.
    """
    if not isinstance(payload, (bytes, bytearray)) or len(payload) != PAYLOAD_LENGTH_BYTES:
        raise ValueError("TigerTag Maker payload must be exactly 80 bytes")
    data = bytes(payload)
    tag = decode_payload(data, uid=uid)
    if tag.id_tigertag != TIGERTAG_TAG_ID or tag.id_product != MAKER_PRODUCT_ID:
        raise ValueError("payload is not an unsigned TigerTag Maker tag")
    # Parsing is intentionally tolerant (for example malformed UTF-8 is
    # decoded with replacement), but bytes accepted for writing must be the
    # one canonical representation emitted by the official SDK. This rejects
    # non-zero reserved bytes and lossy text before they reach the tag.
    if tag.to_bytes() != data:
        raise ValueError(
            "payload is not canonical TigerTag Maker data; use tigertag_encode"
        )
    warnings = tag.validate()
    if warnings:
        raise ValueError("; ".join(warnings))
    return tag
