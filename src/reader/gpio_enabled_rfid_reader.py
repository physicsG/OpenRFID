from time import sleep
from typing import Any, Callable

from reader.mifare_classic_reader import MifareClassicReader
from reader.mifare_ultralight_reader import MifareUltralightReader
from reader.rfid_reader import RfidReader
from reader.scan_result import ScanResult
from bus import OutputPin
from config import get_required_configurable_entity_by_name, TYPE_OUTPUT_PIN, TYPE_RFID_READER
from typing import cast

from tag.mifare_classic_tag_processor import TagAuthentication

class GpioEnabledRfidReader(MifareClassicReader, MifareUltralightReader):
    def __init__(self, config: dict):
        super().__init__(config)
        self.gpio_pins_high = self.get_str_array_from_config("gpio_pins_high", True)
        self.gpio_pins_low = self.get_str_array_from_config("gpio_pins_low", True)
        self.rfid_reader = cast(RfidReader, get_required_configurable_entity_by_name(config["rfid_reader"], TYPE_RFID_READER))

        self.gpio_high : list[OutputPin] = []
        self.gpio_low : list[OutputPin] = []

        for pin in self.gpio_pins_high:
            self.gpio_high.append(cast(OutputPin, get_required_configurable_entity_by_name(pin, TYPE_OUTPUT_PIN)))

        for pin in self.gpio_pins_low:
            self.gpio_low.append(cast(OutputPin, get_required_configurable_entity_by_name(pin, TYPE_OUTPUT_PIN)))

    def start_session(self):
        for pin in self.gpio_high:
            pin.set_high()
        
        for pin in self.gpio_low:
            pin.set_low()

        # Allow channel to settle after changing GPIO states
        sleep(0.100)

        self.rfid_reader.start_session()

    def end_session(self):
        self.rfid_reader.end_session()

    def scan(self) -> ScanResult | None:
        return self.rfid_reader.scan()
    
    def read_mifare_classic(self, scan_result : ScanResult, keys: TagAuthentication) -> bytes|None:
        if isinstance(self.rfid_reader, MifareClassicReader):
            return self.rfid_reader.read_mifare_classic(scan_result, keys)
        
        return None
    
    def read_mifare_ultralight(self, scan_result : ScanResult) -> bytes|None:
        if isinstance(self.rfid_reader, MifareUltralightReader):
            return self.rfid_reader.read_mifare_ultralight(scan_result)
        
        return None

    def _write_ntag_pages_unchecked(self, start_page: int, data: bytes) -> int | None:
        """Private passthrough for the legacy diagnostic NTAG writer."""
        write = getattr(self.rfid_reader, "_write_ntag_pages_unchecked", None)
        if not callable(write):
            return None
        return write(start_page, data)

    def write_tigertag_maker(
        self,
        expected_uid: bytes,
        data: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict:
        """Delegate a safe write after the runtime has opened this session."""
        if not isinstance(self.rfid_reader, MifareUltralightReader):
            return {
                "ok": False,
                "code": "reader_not_supported",
                "error": "inner reader does not support safe TigerTag writes",
            }
        kwargs = {
            "allow_unrecognized": allow_unrecognized,
            "allow_legacy_migration": allow_legacy_migration,
        }
        if safety_check is not None:
            kwargs["safety_check"] = safety_check
        return self.rfid_reader.write_tigertag_maker(expected_uid, data, **kwargs)

    def clear_tigertag_maker(
        self,
        expected_uid: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict:
        """Delegate a safe clear after the runtime has opened this session."""
        if not isinstance(self.rfid_reader, MifareUltralightReader):
            return {
                "ok": False,
                "code": "reader_not_supported",
                "error": "inner reader does not support safe TigerTag clears",
            }
        kwargs = {
            "allow_unrecognized": allow_unrecognized,
            "allow_legacy_migration": allow_legacy_migration,
        }
        if safety_check is not None:
            kwargs["safety_check"] = safety_check
        return self.rfid_reader.clear_tigertag_maker(expected_uid, **kwargs)
