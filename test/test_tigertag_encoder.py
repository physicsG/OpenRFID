"""Official TigerTag SDK adapter and OpenRFID model tests."""

import json
import sys
from pathlib import Path

import pytest
from tigertag import ID_TIGERTAG, ID_TIGERTAG_PLUS, MAKER_PRODUCT_ID, TigerTag

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"

if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from reader.scan_result import ScanResult
from tag.tag_types import TagType
from tag.tigertag import constants as Constants
from tag.tigertag.encoder import (
    PAYLOAD_LENGTH_BYTES,
    PAYLOAD_PAGE_COUNT,
    TIGERTAG_MAKER_PRODUCT_ID,
    TIGERTAG_TAG_ID,
    USER_DATA_END_PAGE,
    USER_DATA_START_PAGE,
    decode_payload,
    encode,
    encode_blank,
    erase,
    get_options,
    validate_maker_payload,
)
from tag.tigertag.processor import TigerTagProcessor


def _build_processor(name: str = "TigerTagProcessor") -> TigerTagProcessor:
    processor = TigerTagProcessor({"__name": name})
    processor.enabled = True
    return processor


def _build_scan_result(uid: bytes = bytes.fromhex("04A1B2C3D4E5F6")) -> ScanResult:
    return ScanResult(
        tag_type=TagType.MifareUltralight,
        uid=uid,
        atqa=b"\x00\x44",
        bcc=b"\x00",
        sak=b"\x00",
    )


def _wrap_user_payload(payload: bytes) -> bytes:
    """Prepend pages 0-3 as returned by the FM175xx full-memory reader."""
    return b"\x00" * Constants.USER_DATA_BYTE_OFFSET + payload


def _minimal_pla_spec() -> dict:
    return {
        "material": "PLA",
        "brand": "ELEGOO",
        "type": "Filament",
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


def test_encoder_uses_exact_maker_owned_pages() -> None:
    assert PAYLOAD_LENGTH_BYTES == 80
    assert PAYLOAD_PAGE_COUNT == 20
    assert USER_DATA_START_PAGE == 4
    assert USER_DATA_END_PAGE == 23
    assert len(encode({})) == PAYLOAD_LENGTH_BYTES
    assert encode_blank() == erase() == b"\x00" * PAYLOAD_LENGTH_BYTES


def test_encoder_emits_official_maker_identity() -> None:
    payload = encode({})
    tag = validate_maker_payload(payload)

    assert TIGERTAG_TAG_ID == ID_TIGERTAG
    assert TIGERTAG_MAKER_PRODUCT_ID == MAKER_PRODUCT_ID
    assert tag.id_tigertag == ID_TIGERTAG
    assert tag.id_product == MAKER_PRODUCT_ID
    assert tag.is_maker


def test_options_are_json_safe_official_sdk_registry_records() -> None:
    options = get_options()
    serialized = json.dumps(options, sort_keys=True)
    assert serialized
    assert options["schema_version"] == 1
    assert options["sdk"] == {
        "name": "tigertag",
        "version": "1.2.1",
        "commit": "f3e2e2e8a1fdf88f91fb43ca4b5c5fbfb88f81af",
    }

    for key in ("materials", "brands", "aspects", "types", "diameters", "units"):
        assert options[key]
        assert all(
            isinstance(record["id"], int) and isinstance(record["label"], str)
            for record in options[key]
        )

    pla = next(record for record in options["materials"] if record["label"] == "PLA")
    assert pla["material_type"] == "PLA"
    assert pla["product_type_id"] == 142
    assert "recommended" in pla

    tricolor = next(record for record in options["aspects"] if record["label"] == "Tricolor")
    bicolor = next(record for record in options["aspects"] if record["label"] == "Bicolor")
    assert tricolor["color_count"] == 3
    assert bicolor["color_count"] == 2

    # Callers cannot mutate the cached SDK database through the returned view.
    options["aspects"][0]["label"] = "mutated"
    assert get_options()["aspects"][0]["label"] != "mutated"


def test_encoder_round_trip_preserves_legacy_spec_fields() -> None:
    payload = encode(_minimal_pla_spec())
    filament = _build_processor().process_tag(_build_scan_result(), _wrap_user_payload(payload))
    assert filament is not None

    assert filament.tag_format == "tigertag"
    assert filament.diameter_mm == pytest.approx(1.75)
    assert filament.weight_grams == pytest.approx(1000.0)
    assert filament.hotend_min_temp_c == pytest.approx(190.0)
    assert filament.hotend_max_temp_c == pytest.approx(240.0)
    assert filament.bed_temp_c == pytest.approx(45.0)
    assert filament.bed_temp_min_c == pytest.approx(45.0)
    assert filament.bed_temp_max_c == pytest.approx(55.0)
    assert filament.drying_temp_c == pytest.approx(50.0)
    assert filament.drying_time_hours == pytest.approx(8.0)
    assert filament.manufacturing_date == "2026-04-03"
    assert filament.message == "Hello, world!"
    assert filament.colors == [0xFFBCBCBC]
    assert filament.authentication is not None
    assert filament.authentication["verification"] == "unsigned"


def test_iso8601_offset_and_z_timestamps_normalize_to_the_same_instant() -> None:
    offset_tag = validate_maker_payload(
        encode({"manufacturing_date": "2026-04-03T02:30:00+02:30"})
    )
    utc_tag = validate_maker_payload(
        encode({"manufacturing_date": "2026-04-03T00:00:00Z"})
    )

    assert offset_tag.timestamp == utc_tag.timestamp


def test_message_whitespace_is_preserved_verbatim() -> None:
    message = "  padded  "
    payload = encode({"message": message})

    assert validate_maker_payload(payload).custom_message == message
    filament = _build_processor().process_tag(
        _build_scan_result(),
        _wrap_user_payload(payload),
    )
    assert filament is not None
    assert filament.message == message


def test_message_limit_is_28_utf8_bytes_without_partial_codepoints() -> None:
    ascii_payload = encode({"message": "x" * 28})
    assert ascii_payload[48:76] == b"x" * 28

    emoji_payload = encode({"message": "\U0001F600" * 7})
    assert emoji_payload[48:76].decode("utf-8") == "\U0001F600" * 7

    with pytest.raises(ValueError, match="28 UTF-8 bytes"):
        encode({"message": "x" * 29})
    with pytest.raises(ValueError, match="28 UTF-8 bytes"):
        encode({"message": "\U0001F600" * 8})


def test_three_colors_quantity_ranges_message_and_td_are_additive() -> None:
    spec = {
        **_minimal_pla_spec(),
        "aspect_1": "Silk",
        "aspect_2": "Tricolor",
        "colors": ["#112233", "#445566", "#778899"],
        "measure": 1000,
        "measure_available": 640,
        "td_mm": 12.5,
        "message": "Galaxy Black",
    }

    payload = encode(spec)
    sdk_tag = validate_maker_payload(payload, uid=_build_scan_result().uid)
    assert sdk_tag.measure == 1000
    assert sdk_tag.measure_available == 640
    assert sdk_tag.td_value == pytest.approx(12.5)
    assert sdk_tag.color2_hex == "#445566"
    assert sdk_tag.color3_hex == "#778899"

    filament = _build_processor("renamed_tigertag_section").process_tag(
        _build_scan_result(),
        _wrap_user_payload(payload),
    )
    assert filament is not None
    assert filament.source_processor == "renamed_tigertag_section"
    assert filament.tag_format == "tigertag"
    assert filament.colors == [0xFF112233, 0xFF445566, 0xFF778899]
    assert filament.available_quantity == pytest.approx(640.0)
    assert filament.quantity_unit == "g"
    assert filament.bed_temp_min_c == pytest.approx(45.0)
    assert filament.bed_temp_max_c == pytest.approx(55.0)
    assert filament.message == "Galaxy Black"
    assert filament.td == pytest.approx(12.5)
    assert {"message", "td", "td_mm", "available_quantity", "bed_temp_max_c"} <= set(
        filament.present_fields
    )
    assert filament.format_data["product"]["mode"] == "maker"
    assert filament.format_data["product_type"]["label"] == "Filament"
    assert filament.format_data["raw"]["measure_available"] == 640
    assert filament.authentication["verification"] == "unsigned"

    serialized = filament.to_dict()
    assert serialized["tag_format"] == "tigertag"
    assert serialized["bed_temp_min_c"] == pytest.approx(45.0)
    assert serialized["td_mm"] == pytest.approx(12.5)
    assert serialized["colors_rgba_hex"] == ["112233FF", "445566FF", "778899FF"]


def test_sdk_adapter_decodes_init_plus_and_signed_lengths() -> None:
    uid = _build_scan_result().uid

    init = TigerTag.as_init(uid=uid)
    decoded_init = decode_payload(init.to_bytes(), uid=uid)
    assert decoded_init.is_init

    plus = TigerTag.create(product_id=1234, uid=uid, id_material=38219)
    decoded_plus = decode_payload(plus.to_bytes(), uid=uid)
    assert not decoded_plus.is_maker
    assert not decoded_plus.is_init
    assert decoded_plus.id_product == 1234

    signed_length = plus.to_bytes(include_signature=True)
    assert len(signed_length) == 144
    assert decode_payload(signed_length, uid=uid).id_product == 1234


def test_real_signed_plus_fixture_reports_valid_and_wrong_uid_invalid() -> None:
    fixture_path = (
        Path(__file__).resolve().parent
        / "tags"
        / "Tigertag"
        / "eSun PLA Basic Refill Cold White TigerTag+.bin"
    )
    dump = fixture_path.read_bytes()
    uid = dump[0:3] + dump[4:8]

    verified = _build_processor().process_tag(_build_scan_result(uid), dump)
    assert verified is not None
    assert verified.format_data["variant"] == "plus"
    assert verified.authentication == {
        "signed": True,
        "verification": "valid",
        "sdk_verification": "valid",
        "ok": True,
        "detail": "",
    }

    wrong_uid = uid[:-1] + bytes([uid[-1] ^ 0x01])
    invalid = _build_processor().process_tag(_build_scan_result(wrong_uid), dump)
    assert invalid is not None
    assert invalid.authentication["signed"] is True
    assert invalid.authentication["verification"] == "invalid"
    assert invalid.authentication["ok"] is False


def test_legacy_96_byte_plus_product_zero_is_explicitly_classified() -> None:
    canonical = encode(_minimal_pla_spec())
    # The old feature writer emitted a 96-byte body with the Plus format ID,
    # product 0, and a zero signature fragment. A full FM read supplies at
    # least 144 user bytes, all zero after that legacy body.
    legacy_body = bytearray(144)
    legacy_body[:80] = canonical
    legacy_body[0:4] = ID_TIGERTAG_PLUS.to_bytes(4, "big")
    legacy_body[4:8] = bytes(4)
    filament = _build_processor().process_tag(
        _build_scan_result(),
        _wrap_user_payload(bytes(legacy_body)),
    )
    assert filament is not None
    assert filament.manufacturer == "ELEGOO"
    assert filament.type == "PLA"
    assert filament.message == "Hello, world!"
    assert filament.format_data["variant"] == "legacy_openrfid_v1"
    assert filament.format_data["raw"]["id_tigertag"] == ID_TIGERTAG_PLUS
    assert filament.format_data["raw"]["id_product"] == 0
    assert filament.authentication["signed"] is False
    assert filament.authentication["verification"] == "legacy_openrfid_v1"
    assert filament.authentication["sdk_verification"] == "unsigned"
    assert "rewrite explicitly as a Maker tag" in filament.authentication["detail"]


def test_legacy_detection_uses_zero_signature_prefix_not_unrelated_tail() -> None:
    legacy_body = bytearray(144)
    legacy_body[:80] = encode(_minimal_pla_spec())
    legacy_body[0:4] = ID_TIGERTAG_PLUS.to_bytes(4, "big")
    legacy_body[4:8] = bytes(4)
    # Pages 24..27 remain the guaranteed zero prefix from the old 96-byte
    # writer, while later untouched memory contains stale non-zero bytes.
    legacy_body[96] = 0xA5

    filament = _build_processor().process_tag(
        _build_scan_result(),
        _wrap_user_payload(bytes(legacy_body)),
    )
    assert filament is not None
    assert filament.format_data["variant"] == "legacy_openrfid_v1"
    assert filament.authentication["signed"] is False
    assert filament.authentication["stale_signature_tail"] is True
    assert any("stale bytes" in warning for warning in filament.format_data["validation_warnings"])


@pytest.mark.parametrize(
    ("unit", "measure", "expected_weight"),
    [
        ("kg", 2, 2000.0),
        ("mg", 2500, 2.5),
        ("m", 1000, None),
        ("ml", 750, None),
    ],
)
def test_quantity_units_only_project_weight_units_to_grams(unit, measure, expected_weight) -> None:
    payload = encode({**_minimal_pla_spec(), "unit": unit, "measure": measure})
    filament = _build_processor().process_tag(
        _build_scan_result(),
        _wrap_user_payload(payload),
    )
    assert filament is not None
    assert filament.available_quantity == pytest.approx(float(measure))
    assert filament.quantity_unit == unit
    assert filament.weight_grams == expected_weight
    assert ("weight_grams" in filament.present_fields) is (expected_weight is not None)


@pytest.mark.parametrize("offset", [39, 43, 46, 47, 79])
def test_maker_validation_rejects_noncanonical_reserved_bytes(offset) -> None:
    payload = bytearray(encode(_minimal_pla_spec()))
    payload[offset] = 0xA5
    with pytest.raises(ValueError, match="not canonical"):
        validate_maker_payload(bytes(payload))


def test_maker_validation_rejects_lossy_invalid_utf8() -> None:
    payload = bytearray(encode(_minimal_pla_spec()))
    payload[48:76] = b"\xFF" + bytes(27)
    with pytest.raises(ValueError, match="not canonical"):
        validate_maker_payload(bytes(payload))


@pytest.mark.parametrize(
    ("payload", "variant"),
    [
        (TigerTag.as_init().to_bytes(), "init"),
        (encode({}), "maker"),
    ],
)
def test_init_and_empty_maker_remain_identifiable_without_printer_material(payload, variant) -> None:
    filament = _build_processor().process_tag(
        _build_scan_result(),
        _wrap_user_payload(payload),
    )
    assert filament is not None
    assert filament.tag_format == "tigertag"
    assert filament.format_data["variant"] == variant
    assert filament.type_supported is False
    assert filament.to_dict()["type_supported"] is False


def test_every_official_material_option_round_trips_through_processor() -> None:
    processor = _build_processor()
    failures = []
    for material in get_options()["materials"]:
        try:
            payload = encode({
                "material": material["id"],
                "type": material.get("product_type_id") or 142,
                "diameter": 56,
                "unit": 21,
                "color": "#112233",
                "measure": 1000,
            })
            filament = processor.process_tag(
                _build_scan_result(),
                _wrap_user_payload(payload),
            )
            if filament is None:
                failures.append(material["label"])
        except Exception as exc:  # collect all registry failures in one assertion
            failures.append(f"{material['label']}: {exc}")

    assert failures == []


def test_maker_validation_rejects_wrong_length_and_non_maker_models() -> None:
    with pytest.raises(ValueError, match="exactly 80"):
        validate_maker_payload(bytes(96))

    plus = TigerTag.create(product_id=1234).to_bytes()
    with pytest.raises(ValueError, match="not an unsigned TigerTag Maker"):
        validate_maker_payload(plus)

    with pytest.raises(ValueError, match="only encode unsigned TigerTag Maker"):
        encode({"product_id": 1234})
