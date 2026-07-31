import hashlib
from typing import Any

from .valid_materials import VALID_BASE_MATERIALS

def to_rgba(argb: int) -> int:
    a = (argb >> 24) & 0xFF
    r = (argb >> 16) & 0xFF
    g = (argb >> 8) & 0xFF
    b = argb & 0xFF

    rgba = (r << 24) | (g << 16) | (b << 8) | a
    return rgba

class GenericFilament:
    def __init__(self,
                 source_processor: str,
                 unique_id: str,
                 manufacturer: str,
                 type: str, # TODO: Should probably be an enum?
                 modifiers: list[str],
                 colors : list[int], # Format 0xAARRGGBB
                 diameter_mm: float,
                 weight_grams: float | None,
                 hotend_min_temp_c: float,
                 hotend_max_temp_c: float,
                 bed_temp_c: float,
                 drying_temp_c: float,
                 drying_time_hours: float,
                 manufacturing_date: str, # ISO 8601 date string
                 td: float | None = None, # Transmission Distance in mm for HueForge/OrcaSlicer-FullSpectrum
                 bed_temp_max_c: float | None = None,
                 message: str | None = None, # On-tag custom message; separate from an inventory/display name.
                 tag_format: str = "unknown",
                 present_fields: list[str] | None = None,
                 format_data: dict[str, Any] | None = None,
                 authentication: dict[str, Any] | None = None,
                 available_quantity: float | None = None,
                 quantity_unit: str | None = None,
                 bed_temp_min_c: float | None = None,
                 material_name: str | None = None,
                 ):
        self.source_processor = source_processor
        self.unique_id = unique_id
        self.manufacturer = manufacturer
        self.type = type
        self.modifiers = modifiers
        self.colors = colors
        self.diameter_mm = diameter_mm
        self.weight_grams = weight_grams
        self.hotend_min_temp_c = hotend_min_temp_c
        self.hotend_max_temp_c = hotend_max_temp_c
        self.bed_temp_min_c = bed_temp_c if bed_temp_min_c is None else bed_temp_min_c
        # Keep the historical key as an alias for the minimum of the range.
        self.bed_temp_c = self.bed_temp_min_c
        self.drying_temp_c = drying_temp_c
        self.drying_time_hours = drying_time_hours
        self.manufacturing_date = manufacturing_date
        self.td = 0.0 if td is None else td
        self.td_mm = self.td
        self.bed_temp_max_c = 0.0 if bed_temp_max_c is None else bed_temp_max_c
        self.message = "" if message is None else message
        self.tag_format = str(tag_format or "unknown").strip().lower()
        self.format_data = dict(format_data or {})
        self.authentication = dict(authentication) if authentication is not None else None
        self.available_quantity = available_quantity
        self.quantity_unit = quantity_unit
        # Preserve a format's exact material/product label separately from the
        # normalized printer profile type (for example "PLA Marble" vs PLA).
        self.material_name = material_name

        if present_fields is None:
            inferred_fields = [
                "manufacturer",
                "type",
                "modifiers",
                "colors",
                "colors_rgba",
                "colors_rgba_hex",
                "diameter_mm",
                "hotend_min_temp_c",
                "hotend_max_temp_c",
                "bed_temp_c",
                "bed_temp_min_c",
                "drying_temp_c",
                "drying_time_hours",
                "manufacturing_date",
            ]
            if weight_grams is not None:
                inferred_fields.append("weight_grams")
            if bed_temp_max_c is not None:
                inferred_fields.append("bed_temp_max_c")
            if td is not None:
                inferred_fields.extend(("td", "td_mm"))
            if message is not None:
                inferred_fields.append("message")
            if available_quantity is not None:
                inferred_fields.append("available_quantity")
            if quantity_unit is not None:
                inferred_fields.append("quantity_unit")
            if material_name is not None:
                inferred_fields.append("material_name")
            present_fields = inferred_fields

        # Preserve caller order while removing duplicates and malformed entries.
        self.present_fields = list(dict.fromkeys(
            field for field in present_fields
            if isinstance(field, str) and field
        ))

        if "CF" in self.modifiers:
            self.type += "-CF"
            self.modifiers.remove("CF")
        
        if "GF" in self.modifiers:
            self.type += "-GF"
            self.modifiers.remove("GF")

        # A recognized RFID payload may legitimately contain a material that
        # the printer's historical profile whitelist does not know yet. Keep
        # that decoded identity visible and mark projection support instead of
        # turning the entire tag into a parse error (notably official Init,
        # empty Maker, and newer TigerTag registry entries).
        self.type_supported = self.type in VALID_BASE_MATERIALS

    def pretty_text(self) -> str:
        modifiers = ' '.join(self.modifiers)

        if modifiers:
            modifiers += " "

        return "\n".join([
            f"{self.manufacturer} {self.type} {modifiers}Filament (processed by {self.source_processor}):",
            f"- Color (ARGB): {' '.join([f'#{color:06X}' for color in self.colors])}",
            f"- Diameter: {self.diameter_mm:.2f} mm",
            f"- Weight: {self.weight_grams} grams",
            f"- Hotend Temp: {self.hotend_min_temp_c:.1f}C - {self.hotend_max_temp_c:.1f}C",
            f"- Bed Temp: {self.bed_temp_c:.1f}C",
            f"- Drying: {self.drying_temp_c:.1f}C for {self.drying_time_hours:.1f} hours",
            f"- Manufactured on: {self.manufacturing_date}",
            f"- TD: {self.td:.1f} mm"
        ])

    @property
    def rgba(self) -> int:
        if not self.colors or len(self.colors) == 0:
            return 0x00000000  # Transparent if no color available
        
        argb = self.colors[0]
        return to_rgba(argb)
    
    def to_dict(self) -> dict:
        return {
            "source_processor": self.source_processor,
            "tag_format": self.tag_format,
            "unique_id": self.unique_id,
            "manufacturer": self.manufacturer,
            "type": self.type,
            "type_supported": self.type_supported,
            "material_name": self.material_name,
            "modifiers": self.modifiers,
            "colors": self.colors,
            "rgba": self.rgba,
            "rgb": (self.rgba >> 8) & 0xFFFFFF,
            "alpha": self.rgba & 0xFF,
            "colors_rgba": [to_rgba(color) for color in self.colors],
            "colors_rgba_hex": [f"{to_rgba(color):08X}" for color in self.colors],
            "diameter_mm": self.diameter_mm,
            "weight_grams": self.weight_grams,
            "hotend_min_temp_c": self.hotend_min_temp_c,
            "hotend_max_temp_c": self.hotend_max_temp_c,
            "bed_temp_c": self.bed_temp_c,
            "bed_temp_min_c": self.bed_temp_min_c,
            "bed_temp_max_c": self.bed_temp_max_c,
            "drying_temp_c": self.drying_temp_c,
            "drying_time_hours": self.drying_time_hours,
            "manufacturing_date": self.manufacturing_date,
            "td": self.td,
            "td_mm": self.td_mm,
            "message": self.message,
            "available_quantity": self.available_quantity,
            "quantity_unit": self.quantity_unit,
            "present_fields": self.present_fields,
            "format_data": self.format_data,
            "authentication": self.authentication,
        }
    
    @staticmethod
    def generate_unique_id(*args) -> str:
        strings = "|".join([str(arg) for arg in args])
        hash = hashlib.sha256(strings.encode('utf-8')).hexdigest()
        return hash
