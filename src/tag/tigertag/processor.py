from __future__ import annotations

from typing import Any

from filament import GenericFilament
from reader.scan_result import ScanResult
from tag.mifare_ultralight_tag_processor import MifareUltralightTagProcessor
from tag.tag_types import TagType
from tigertag import ID_TIGERTAG_PLUS, INIT_PRODUCT_ID, TigerTag, TigerTagDB

from . import constants as Constants
from .encoder import decode_payload


class TigerTagProcessor(MifareUltralightTagProcessor):
    tag_format = "tigertag"

    def __init__(self, config: dict):
        super().__init__(config)
        self.db = TigerTagDB()

    def process_tag(self, scan_result: ScanResult, data: bytes) -> GenericFilament | None:
        if scan_result.tag_type != TagType.MifareUltralight:
            return None

        payload = self.__extract_payload(data)
        if payload is None:
            return None

        tag_id = int.from_bytes(payload[Constants.OFF_TAG_ID:Constants.OFF_TAG_ID + 4], "big")
        if tag_id not in Constants.TIGERTAG_VALID_DATA_IDS:
            return None

        try:
            uid = scan_result.uid if len(scan_result.uid) == 7 else None
            tag = decode_payload(payload, uid=uid)
            self.logger.debug(
                "TigerTag: Detected format ID 0x%08X (%s)",
                tag.id_tigertag,
                TigerTagDB.label(self.db.version(tag.id_tigertag)),
            )
            return self.__to_generic_filament(
                tag,
                has_signature_region=len(payload) == 144,
            )
        except Exception as exc:
            self.logger.exception("TigerTag: Failed to parse tag data: %s", exc)
            return None

    @staticmethod
    def __extract_payload(data: bytes) -> bytes | None:
        if not isinstance(data, (bytes, bytearray)):
            return None
        raw = bytes(data)

        # Unit tests and integrations may already supply user pages only.
        if len(raw) in (80, 144):
            return raw

        # The FM175xx reader supplies complete chip memory. Pages 0-3 occupy
        # the first 16 bytes; retain the signature pages when they are present.
        user_data = raw[Constants.USER_DATA_BYTE_OFFSET:]
        if len(user_data) >= 144:
            return user_data[:144]
        if len(user_data) >= Constants.MIN_DATA_LENGTH:
            # This also keeps semantic compatibility with the former 96-byte
            # encoder: its first 80 bytes are the standard TigerTag body and
            # its trailing zero signature fragment is ignored.
            return user_data[:Constants.MIN_DATA_LENGTH]
        return None

    def __to_generic_filament(
        self,
        tag: TigerTag,
        has_signature_region: bool,
    ) -> GenericFilament:
        enriched = tag.to_dict(self.db)
        raw = tag.to_raw_dict()

        material_entry = self.db.material(tag.id_material) or {}
        material_label = TigerTagDB.label(material_entry)
        material_type = material_entry.get("material_type") or material_label
        filled_type = material_entry.get("filled_type") or ""
        resolved_material_type = (
            f"{material_type}-{filled_type}"
            if filled_type and not str(material_type).endswith(f"-{filled_type}")
            else str(material_type)
        )

        brand_name = TigerTagDB.label(self.db.brand(tag.id_brand))
        diameter_label = TigerTagDB.label(self.db.diameter(tag.id_diameter))
        try:
            diameter_mm = float(diameter_label)
        except (TypeError, ValueError):
            diameter_mm = 0.0

        aspect_entries = [
            self.db.aspect(tag.id_aspect_1) or {},
            self.db.aspect(tag.id_aspect_2) or {},
        ]
        aspect_labels = [
            TigerTagDB.label(entry)
            for entry in aspect_entries
            if entry
        ]
        modifiers = [
            label for label in aspect_labels
            if label not in ("", "-", "None", "Unknown")
        ]

        active_color_count = self.__active_color_count(aspect_entries)
        colors = self.__active_colors(tag, active_color_count)

        unit_entry = self.db.unit(tag.id_unit) or {}
        quantity_unit = TigerTagDB.label(unit_entry)
        weight_grams = self.__to_grams(tag.measure, unit_entry)

        verification = tag.verify(self.db).to_dict()
        # OpenRFID's retired 96-byte writer used a Plus/product-0 header and
        # guaranteed zero bytes in pages 24..27 (the first 16 signature
        # bytes). Do not classify arbitrary unsigned Plus-shaped records as
        # migratable; the physical writer repeats this exact read-only check.
        is_legacy_openrfid_v1 = (
            tag.id_tigertag == ID_TIGERTAG_PLUS
            and tag.id_product == INIT_PRODUCT_ID
            and has_signature_region
            and tag.signature_r[:16] == bytes(16)
        )
        legacy_stale_signature_tail = is_legacy_openrfid_v1 and bool(
            any(tag.signature_r[16:]) or any(tag.signature_s)
        )
        variant = (
            "legacy_openrfid_v1"
            if is_legacy_openrfid_v1
            else "plus"
            if tag.id_tigertag == ID_TIGERTAG_PLUS
            else "init"
            if tag.is_init
            else "maker"
        )
        authentication = {
            "signed": False if is_legacy_openrfid_v1 else tag.is_signed,
            "verification": (
                "legacy_openrfid_v1"
                if is_legacy_openrfid_v1
                else verification.get("status", "unavailable")
            ),
            "sdk_verification": verification.get("status", "unavailable"),
            "ok": False if is_legacy_openrfid_v1 else bool(verification.get("ok", False)),
            "detail": (
                "Legacy OpenRFID TigerTag encoding: Plus format ID with product 0 "
                "and no signature. Data is readable but not authenticated; rewrite "
                "explicitly as a Maker tag to upgrade it."
                if is_legacy_openrfid_v1
                else verification.get("detail", "")
            ),
        }
        if is_legacy_openrfid_v1:
            authentication["stale_signature_tail"] = legacy_stale_signature_tail

        present_fields = [
            "manufacturer",
            "type",
            "type_supported",
            "material_name",
            "modifiers",
            "colors",
            "colors_rgba",
            "colors_rgba_hex",
            "diameter_mm",
            "available_quantity",
            "quantity_unit",
            "hotend_min_temp_c",
            "hotend_max_temp_c",
            "bed_temp_c",
            "bed_temp_min_c",
            "bed_temp_max_c",
            "drying_temp_c",
            "drying_time_hours",
            "manufacturing_date",
        ]
        if weight_grams is not None:
            present_fields.append("weight_grams")
        if tag.custom_message:
            present_fields.append("message")
        if tag.td_raw:
            present_fields.extend(("td", "td_mm"))

        validation_warnings = list(tag.validate())
        if legacy_stale_signature_tail:
            validation_warnings.append(
                "legacy OpenRFID v1 tag has non-zero stale bytes after its guaranteed zero signature prefix"
            )

        format_data: dict[str, Any] = {
            "sdk": enriched.get("sdk"),
            "protocol": enriched.get("protocol"),
            "variant": variant,
            "version": enriched.get("version"),
            "product": enriched.get("product"),
            "product_type": enriched.get("type"),
            "material": enriched.get("material"),
            "aspects": [enriched.get("aspect_1"), enriched.get("aspect_2")],
            "colors": enriched.get("colors"),
            "measure": enriched.get("measure"),
            "temperatures": enriched.get("temperatures"),
            "twin_tag_pairing_id": enriched.get("twin_tag_pairing_id"),
            # Keep raw on-chip values separate from SDK database enrichment.
            "raw": raw,
            "validation_warnings": validation_warnings,
            "legacy": {
                "signature_prefix_zero": is_legacy_openrfid_v1,
                "stale_signature_tail": legacy_stale_signature_tail,
            } if is_legacy_openrfid_v1 else None,
        }

        primary_color = colors[0] if colors else 0
        self.logger.debug("Found TigerTag filament:")
        self.logger.debug("  Product: %s", enriched.get("product"))
        self.logger.debug("  Material: %s", resolved_material_type)
        self.logger.debug("  Brand: %s", brand_name)
        self.logger.debug("  Colors (ARGB): %s", [f"0x{color:08X}" for color in colors])
        self.logger.debug("  Available: %d %s", tag.measure_available, quantity_unit)
        self.logger.debug("  Authentication: %s", authentication["verification"])

        return GenericFilament(
            source_processor=self.name,
            tag_format=self.tag_format,
            unique_id=GenericFilament.generate_unique_id(
                "TigerTag",
                brand_name,
                resolved_material_type,
                primary_color,
                tag.id_product,
                tag.timestamp,
            ),
            manufacturer=brand_name,
            type=resolved_material_type,
            material_name=material_label,
            modifiers=modifiers,
            colors=colors,
            diameter_mm=diameter_mm,
            weight_grams=weight_grams,
            available_quantity=float(tag.measure_available),
            quantity_unit=quantity_unit,
            hotend_min_temp_c=float(tag.nozzle_temp_min),
            hotend_max_temp_c=float(tag.nozzle_temp_max),
            bed_temp_c=float(tag.bed_temp_min),
            bed_temp_min_c=float(tag.bed_temp_min),
            bed_temp_max_c=float(tag.bed_temp_max),
            drying_temp_c=float(tag.dry_temp),
            drying_time_hours=float(tag.dry_time),
            manufacturing_date=tag.manufacturing_date.strftime("%Y-%m-%d"),
            td=tag.td_value,
            message=tag.custom_message,
            present_fields=present_fields,
            format_data=format_data,
            authentication=authentication,
        )

    @staticmethod
    def __active_color_count(aspect_entries: list[dict]) -> int:
        first_count = int(aspect_entries[0].get("color_count", 0) or 0)
        second_count = int(aspect_entries[1].get("color_count", 0) or 0)
        # TigerTag defines multi-color mode on aspect 2 first, then aspect 1.
        if second_count > 1:
            return min(second_count, 3)
        if first_count > 1:
            return min(first_count, 3)
        return 1

    @staticmethod
    def __active_colors(tag: TigerTag, count: int) -> list[int]:
        primary = (
            (tag.color1_a << 24)
            | (tag.color1_r << 16)
            | (tag.color1_g << 8)
            | tag.color1_b
        )
        secondary = (
            (0xFF << 24)
            | (tag.color2_r << 16)
            | (tag.color2_g << 8)
            | tag.color2_b
        )
        tertiary = (
            (0xFF << 24)
            | (tag.color3_r << 16)
            | (tag.color3_g << 8)
            | tag.color3_b
        )
        return [primary, secondary, tertiary][:count]

    @staticmethod
    def __to_grams(value: int, unit_entry: dict) -> float | None:
        # TigerTag also defines volume, length, and area units. Keep those in
        # available_quantity/quantity_unit without misrepresenting them as a
        # filament weight.
        if unit_entry.get("type") != "weight":
            return None
        unit_id = int(unit_entry.get("id", 0) or 0)
        if unit_id == 21:  # g
            return float(value)
        if unit_id == 35:  # kg
            return float(value) * 1000.0
        if unit_id == 10:  # mg
            return float(value) / 1000.0
        return None
