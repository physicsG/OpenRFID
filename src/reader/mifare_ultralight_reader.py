from abc import abstractmethod
from typing import Any, Callable

from reader.rfid_reader import RfidReader
from reader.scan_result import ScanResult


TIGERTAG_MAKER_ID = 0x5BF59264
TIGERTAG_INIT_ID = 0x6C41A2E1
TIGERTAG_PLUS_ID = 0xBC0FCB97
TIGERTAG_OWNED_START_PAGE = 4
TIGERTAG_OWNED_END_PAGE = 23
TIGERTAG_OWNED_LENGTH = (
    TIGERTAG_OWNED_END_PAGE - TIGERTAG_OWNED_START_PAGE + 1
) * 4

class MifareUltralightReader(RfidReader):
    def __init__(self, config: dict):
        super().__init__(config)

    @abstractmethod
    def read_mifare_ultralight(self, scan_result : ScanResult) -> bytes|None:
        """Reads data from a Mifare Ultralight tag."""
        raise NotImplementedError("Subclasses must implement this method")

    def write_tigertag_maker(
        self,
        expected_uid: bytes,
        data: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Safely replace pages 4..23 with a TigerTag Maker payload.

        The caller owns the reader session. Implementations must verify the
        activated tag and the complete write, and must never expand the owned
        region beyond pages 4..23.
        """
        return {
            "ok": False,
            "code": "reader_not_supported",
            "error": "reader does not support safe TigerTag writes",
        }

    def clear_tigertag_maker(
        self,
        expected_uid: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Safely clear exactly the TigerTag-owned pages 4..23.

        The caller owns the reader session. The same identity, hardware,
        capacity and existing-format checks as :meth:`write_tigertag_maker`
        apply.
        """
        return {
            "ok": False,
            "code": "reader_not_supported",
            "error": "reader does not support safe TigerTag clears",
        }
