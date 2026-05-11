"""TigerTag 96-byte payload encoder.

The encoder mirrors the byte layout consumed by :mod:`tag.tigertag.processor`.
Output is the 96-byte block written starting at NTAG215 user page 4
(``Constants.USER_DATA_PAGE_OFFSET``), suitable for handing to
:meth:`reader.fm175xx.rfid.Fm175xx.write_ntag_pages`.

The encoder loads label-to-id lookup tables from the bundled TigerTag JSON
database under ``tag/tigertag/database/`` (same directory used by
:mod:`tag.tigertag.registry`) so callers can pass either numeric ids or
human-readable labels for the registry-backed fields.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import constants as Constants


_DB_DIRECTORY = Path(__file__).resolve().parent / "database"

# label.lower() -> id, per registry kind
_LABEL_INDEX_CACHE: dict[str, dict[str, int]] | None = None
_LABEL_INDEX_LOCK = threading.Lock()

_DB_FILES = {
    "material": "id_material.json",
    "brand": "id_brand.json",
    "aspect": "id_aspect.json",
    "diameter": "id_diameter.json",
    "unit": "id_measure_unit.json",
    "type": "id_type.json",
}

# Pages 4..N inclusive: TigerTag user payload starts at user-data page 4.
USER_DATA_START_PAGE = Constants.USER_DATA_PAGE_OFFSET
PAYLOAD_LENGTH_BYTES = Constants.MIN_DATA_LENGTH

# Tag IDs accepted by the parser; the encoder always emits the unsigned
# variant. Both values are accepted on read.
TIGERTAG_TAG_ID = 0xBC0FCB97


def _load_db_file(name: str) -> list[dict]:
    path = _DB_DIRECTORY / name
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items", "results", "response", "content"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _build_label_index(records: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for record in records:
        rid = record.get("id")
        if rid is None:
            continue
        try:
            rid_int = int(rid)
        except (TypeError, ValueError):
            continue
        for key in ("label", "name", "title", "description", "symbol", "value"):
            label = record.get(key)
            if isinstance(label, (int, float)):
                label = str(label)
            if isinstance(label, str) and label.strip():
                out[label.strip().lower()] = rid_int
                break
    return out


def _label_indexes() -> dict[str, dict[str, int]]:
    global _LABEL_INDEX_CACHE
    with _LABEL_INDEX_LOCK:
        if _LABEL_INDEX_CACHE is None:
            _LABEL_INDEX_CACHE = {
                kind: _build_label_index(_load_db_file(filename))
                for kind, filename in _DB_FILES.items()
            }
        return _LABEL_INDEX_CACHE


def _resolve_id(kind: str, value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default
        if stripped.isdigit():
            return int(stripped)
        return _label_indexes().get(kind, {}).get(stripped.lower(), default)
    return default


def _utf8_message_bytes(text: Any, max_bytes: int = Constants.MESSAGE_LENGTH) -> bytes:
    """Encode ``text`` to UTF-8, truncated to ``max_bytes`` without splitting a
    codepoint, right-padded with zeros."""
    if not text:
        return b"\x00" * max_bytes
    enc = str(text).encode("utf-8")
    if len(enc) > max_bytes:
        end = max_bytes
        while end > 0 and (enc[end] & 0xC0) == 0x80:
            end -= 1
        enc = enc[:end]
    return enc + b"\x00" * (max_bytes - len(enc))


def _hex_to_rgba(value: Any) -> tuple[int, int, int, int]:
    """Parse ``#RRGGBB`` / ``RRGGBB`` / ``RRGGBBAA`` / ``[r,g,b,a?]`` to
    ``(R, G, B, A)``. Default is opaque black."""
    default = (0, 0, 0, 0xFF)
    if isinstance(value, (list, tuple)) and len(value) >= 3:
        r = int(value[0]) & 0xFF
        g = int(value[1]) & 0xFF
        b = int(value[2]) & 0xFF
        a = int(value[3]) & 0xFF if len(value) >= 4 else 0xFF
        return (r, g, b, a)
    if not isinstance(value, str):
        return default
    s = value.strip().lstrip("#")
    if len(s) == 6:
        try:
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), 0xFF)
        except ValueError:
            return default
    if len(s) == 8:
        try:
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), int(s[6:8], 16))
        except ValueError:
            return default
    return default


def _resolve_mfg_timestamp(mfg_raw: Any) -> int:
    """Convert a manufacturing-date spec into a TigerTag timestamp (seconds
    since 2000-01-01). Falls back to ``now`` on parse failure."""
    if isinstance(mfg_raw, bool):
        return int(time.time()) - Constants.TIGERTAG_EPOCH_OFFSET
    if isinstance(mfg_raw, (int, float)):
        return int(mfg_raw)
    if isinstance(mfg_raw, str) and mfg_raw.strip():
        s = mfg_raw.strip()
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                # Parse as naive UTC (matches parser, which uses UTC for the inverse).
                dt = datetime.strptime(s[: len(fmt) + 4], fmt).replace(tzinfo=timezone.utc)
                return int(dt.timestamp()) - Constants.TIGERTAG_EPOCH_OFFSET
            except (ValueError, OverflowError):
                continue
    return int(time.time()) - Constants.TIGERTAG_EPOCH_OFFSET


def encode(spec: dict) -> bytes:
    """Encode a TigerTag spec dict into a 96-byte user-data block.

    All multi-byte fields are big-endian. The signature region (bytes 80..95)
    is left zeroed; the parser does not enforce a signature.

    Spec fields (all optional unless noted)::

      material:           str label or numeric id   (default 0)
      brand:              str label or numeric id   (default 0)
      aspect_1:           str label or numeric id   (default 0)
      aspect_2:           str label or numeric id   (default 0)
      type:               str label or numeric id   (default 0)
      diameter:           str label or numeric id   (e.g. "1.75")
      product_id:         int 0..0xFFFFFFFF         (default 0)
      color:              "#RRGGBB" / "RRGGBBAA" / [r,g,b,a]  (default opaque black)
      weight_g:           int 0..16777215           (3-byte BE)
      unit:               str label or numeric id   (default 0)
      temp_min_c:         int 0..65535
      temp_max_c:         int 0..65535
      dry_temp_c:         int 0..255
      dry_time_h:         int 0..255
      bed_temp_min_c:     int 0..255
      bed_temp_max_c:     int 0..255
      td_mm:              float 0..6553.5           (encoded as round(mm * 10))
      td:                 int 0..65535              (legacy raw, ignored if td_mm given)
      manufacturing_date: ISO date/datetime str or epoch number
      message:            str up to 28 UTF-8 bytes  (written at OFF_MESSAGE)
    """
    if not isinstance(spec, dict):
        spec = {}

    buf = bytearray(PAYLOAD_LENGTH_BYTES)

    # Header / IDs
    buf[Constants.OFF_TAG_ID:Constants.OFF_TAG_ID + 4] = TIGERTAG_TAG_ID.to_bytes(4, "big")
    pid = int(spec.get("product_id", 0) or 0) & 0xFFFFFFFF
    buf[Constants.OFF_PRODUCT_ID:Constants.OFF_PRODUCT_ID + 4] = pid.to_bytes(4, "big")
    mid = _resolve_id("material", spec.get("material"))
    buf[Constants.OFF_MATERIAL_ID:Constants.OFF_MATERIAL_ID + 2] = (mid & 0xFFFF).to_bytes(2, "big")
    buf[Constants.OFF_ASPECT1_ID] = _resolve_id("aspect", spec.get("aspect_1")) & 0xFF
    buf[Constants.OFF_ASPECT2_ID] = _resolve_id("aspect", spec.get("aspect_2")) & 0xFF
    buf[Constants.OFF_TYPE_ID] = _resolve_id("type", spec.get("type")) & 0xFF
    buf[Constants.OFF_DIAMETER_ID] = _resolve_id("diameter", spec.get("diameter")) & 0xFF
    bid = _resolve_id("brand", spec.get("brand"))
    buf[Constants.OFF_BRAND_ID:Constants.OFF_BRAND_ID + 2] = (bid & 0xFFFF).to_bytes(2, "big")

    # Color (RGBA, written R,G,B,A)
    r, g, b, a = _hex_to_rgba(spec.get("color"))
    buf[Constants.OFF_COLOR_RGBA + 0] = r
    buf[Constants.OFF_COLOR_RGBA + 1] = g
    buf[Constants.OFF_COLOR_RGBA + 2] = b
    buf[Constants.OFF_COLOR_RGBA + 3] = a

    # Weight (3-byte BE) + unit
    weight = max(0, min(int(spec.get("weight_g", 0) or 0), 0xFFFFFF))
    buf[Constants.OFF_WEIGHT + 0] = (weight >> 16) & 0xFF
    buf[Constants.OFF_WEIGHT + 1] = (weight >> 8) & 0xFF
    buf[Constants.OFF_WEIGHT + 2] = weight & 0xFF
    buf[Constants.OFF_UNIT_ID] = _resolve_id("unit", spec.get("unit")) & 0xFF

    # Temps
    tmin = max(0, min(int(spec.get("temp_min_c", 0) or 0), 0xFFFF))
    tmax = max(0, min(int(spec.get("temp_max_c", 0) or 0), 0xFFFF))
    buf[Constants.OFF_TEMP_MIN:Constants.OFF_TEMP_MIN + 2] = tmin.to_bytes(2, "big")
    buf[Constants.OFF_TEMP_MAX:Constants.OFF_TEMP_MAX + 2] = tmax.to_bytes(2, "big")
    buf[Constants.OFF_DRY_TEMP] = max(0, min(int(spec.get("dry_temp_c", 0) or 0), 0xFF))
    buf[Constants.OFF_DRY_TIME] = max(0, min(int(spec.get("dry_time_h", 0) or 0), 0xFF))
    buf[Constants.OFF_BED_TEMP_MIN] = max(0, min(int(spec.get("bed_temp_min_c", 0) or 0), 0xFF))
    buf[Constants.OFF_BED_TEMP_MAX] = max(0, min(int(spec.get("bed_temp_max_c", 0) or 0), 0xFF))

    # Manufacturing timestamp (seconds since 2000-01-01)
    ts = max(0, min(_resolve_mfg_timestamp(spec.get("manufacturing_date")), 0xFFFFFFFF))
    buf[Constants.OFF_TIMESTAMP:Constants.OFF_TIMESTAMP + 4] = ts.to_bytes(4, "big")

    # bytes 36..43 reserved — leave zero

    # TD (transmission distance), big-endian uint16, value = mm * 10
    if spec.get("td_mm") is not None:
        try:
            td = int(round(float(spec.get("td_mm") or 0) * 10))
        except (TypeError, ValueError):
            td = 0
    else:
        td = int(spec.get("td", 0) or 0)
    td = max(0, min(td, 0xFFFF))
    buf[Constants.OFF_TD:Constants.OFF_TD + 2] = td.to_bytes(2, "big")

    # bytes 46..47 reserved — leave zero
    # OFF_MESSAGE = 48: 28-byte UTF-8 message + 4 reserved bytes (signature
    # region starts at OFF_SIGNATURE = 80 and is left zeroed).
    buf[Constants.OFF_MESSAGE:Constants.OFF_MESSAGE + Constants.MESSAGE_LENGTH] = _utf8_message_bytes(
        spec.get("message"), max_bytes=Constants.MESSAGE_LENGTH
    )

    return bytes(buf)


def encode_blank() -> bytes:
    """Return a 96-byte payload of zeros (used to erase NTAG215 user pages)."""
    return b"\x00" * PAYLOAD_LENGTH_BYTES
