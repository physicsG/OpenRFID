"""Round-trip tests for the TigerTag encoder.

Verifies that ``encode(spec)`` produces a 96-byte payload that the existing
:class:`TigerTagProcessor` can parse back into a :class:`GenericFilament` whose
fields match the spec.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from reader.scan_result import ScanResult
from tag.tag_types import TagType
from tag.tigertag import constants as Constants
from tag.tigertag.encoder import (
    PAYLOAD_LENGTH_BYTES,
    TIGERTAG_TAG_ID,
    USER_DATA_START_PAGE,
    encode,
    encode_blank,
)
from tag.tigertag.processor import TigerTagProcessor


def _build_processor() -> TigerTagProcessor:
    processor = TigerTagProcessor({"__name": "TigerTagProcessor"})
    processor.enabled = True
    return processor


def _build_scan_result() -> ScanResult:
    return ScanResult(
        tag_type=TagType.MifareUltralight,
        uid=b"\x01\x02\x03\x04",
        atqa=b"\x00\x44",
        bcc=b"\x00",
        sak=b"\x00",
    )


def _wrap_user_payload(payload: bytes) -> bytes:
    """Prepend ``USER_DATA_BYTE_OFFSET`` zero bytes so the parser sees the
    payload at user-data page 4 (the parser slices past the first
    ``USER_DATA_BYTE_OFFSET`` bytes)."""
    return b"\x00" * Constants.USER_DATA_BYTE_OFFSET + payload


def test_encoder_payload_length_and_start_page() -> None:
    assert PAYLOAD_LENGTH_BYTES == 96
    assert USER_DATA_START_PAGE == 4
    assert len(encode({})) == PAYLOAD_LENGTH_BYTES
    assert encode_blank() == b"\x00" * PAYLOAD_LENGTH_BYTES


def test_encoder_emits_tag_id_header() -> None:
    payload = encode({})
    assert int.from_bytes(payload[0:4], "big") == TIGERTAG_TAG_ID


def test_encoder_round_trip_minimal_pla_spec() -> None:
    spec = {
        "material": "PLA",
        "brand": "ELEGOO",
        "diameter": "1.75",
        "color": "#BCBCBC",
        "weight_g": 1000,
        "unit": "g",
        "temp_min_c": 190,
        "temp_max_c": 240,
        "dry_temp_c": 50,
        "dry_time_h": 8,
        "bed_temp_min_c": 45,
        "bed_temp_max_c": 55,
        "td_mm": 0.0,
        "manufacturing_date": "2026-04-03",
        "message": "Hello, world!",
    }

    payload = encode(spec)
    assert len(payload) == PAYLOAD_LENGTH_BYTES

    filament = _build_processor().process_tag(_build_scan_result(), _wrap_user_payload(payload))
    assert filament is not None

    assert filament.diameter_mm == pytest.approx(1.75)
    assert filament.weight_grams == pytest.approx(1000.0)
    assert filament.hotend_min_temp_c == pytest.approx(190.0)
    assert filament.hotend_max_temp_c == pytest.approx(240.0)
    assert filament.bed_temp_c == pytest.approx(45.0)
    assert filament.bed_temp_max_c == pytest.approx(55.0)
    assert filament.drying_temp_c == pytest.approx(50.0)
    assert filament.drying_time_hours == pytest.approx(8.0)
    assert filament.manufacturing_date == "2026-04-03"
    assert filament.message == "Hello, world!"

    # Color: encoder takes "#RRGGBB" (opaque). Parser stores ARGB, alpha=0xFF.
    assert filament.colors == [(0xFF << 24) | (0xBC << 16) | (0xBC << 8) | 0xBC]


def test_encoder_message_truncation_and_padding() -> None:
    long_msg = "x" * 100
    payload = encode({"message": long_msg})
    msg_region = payload[Constants.OFF_MESSAGE:Constants.OFF_MESSAGE + Constants.MESSAGE_LENGTH]
    assert msg_region == b"x" * Constants.MESSAGE_LENGTH

    short_payload = encode({"message": "ab"})
    short_region = short_payload[Constants.OFF_MESSAGE:Constants.OFF_MESSAGE + Constants.MESSAGE_LENGTH]
    assert short_region == b"ab" + b"\x00" * (Constants.MESSAGE_LENGTH - 2)


def test_encoder_message_does_not_split_utf8_codepoint() -> None:
    # 4-byte UTF-8 emoji repeated; should truncate at a codepoint boundary.
    payload = encode({"message": "\U0001F600" * 10})  # 😀 × 10 = 40 bytes
    msg_region = payload[Constants.OFF_MESSAGE:Constants.OFF_MESSAGE + Constants.MESSAGE_LENGTH]
    # Decoding the truncated region must succeed without errors.
    decoded = msg_region.rstrip(b"\x00").decode("utf-8")
    assert decoded == "\U0001F600" * 7  # 28 bytes / 4 bytes per emoji = 7
