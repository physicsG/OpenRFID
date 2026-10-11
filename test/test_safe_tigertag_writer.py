"""Unit tests for the FM175XX guarded TigerTag Maker transaction."""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# Reader modules import the Linux-only SPI/GPIO packages at module import
# time. These tests bypass hardware construction, so tiny import stubs are
# sufficient on development hosts that do not provide those packages.
sys.modules.setdefault("spidev", types.SimpleNamespace(SpiDev=object))
sys.modules.setdefault(
    "gpiod",
    types.SimpleNamespace(Chip=object, LINE_REQ_DIR_OUT=0),
)

from reader.fm175xx import constants as Constants
from reader.fm175xx.rfid import Fm175xx, Fm175xxReturnVal
from reader.gpio_enabled_rfid_reader import GpioEnabledRfidReader
from reader.mifare_ultralight_reader import (
    MifareUltralightReader,
    TIGERTAG_INIT_ID,
    TIGERTAG_MAKER_ID,
    TIGERTAG_PLUS_ID,
    TIGERTAG_OWNED_LENGTH,
)


UID = bytes.fromhex("04112233445566")
MAKER_PAYLOAD = TIGERTAG_MAKER_ID.to_bytes(4, "big") + bytes(range(TIGERTAG_OWNED_LENGTH - 4))


class _FmHarness:
    def __init__(self, existing_header: int = TIGERTAG_MAKER_ID, existing_product: int = 0):
        self.memory = bytearray(231 * 4)
        self.memory[4 * 4:4 * 4 + 4] = existing_header.to_bytes(4, "big")
        self.memory[5 * 4:5 * 4 + 4] = existing_product.to_bytes(4, "big")
        self.uid = UID
        self.sak = b"\x04\x00"
        self.activate_status = Constants.FM175XX_OK
        self.read_fail_pages: set[int] = set()
        self.write_fail_pages: set[int] = set()
        self.ignore_write_pages: set[int] = set()
        self.read_calls: list[int] = []
        self.write_calls: list[tuple[int, bytes]] = []
        self.version_storage = 0x11

        # Default NTAG215 CFG0.AUTH0 disables password protection.
        self.memory[(130 + 1) * 4 + 3] = 0xFF

        self.reader = object.__new__(Fm175xx)
        self.reader.logger = logging.getLogger("test.safe_tigertag_writer")
        self.reader._Fm175xx__reader_a_activate = self.activate
        self.reader._Fm175xx__reader_a_ultralight_page_read = self.read_pages
        self.reader._Fm175xx__ntag_page_write = self.write_page
        self.reader._Fm175xx__ntag_get_version = self.get_version

    def get_version(self) -> Fm175xxReturnVal:
        result = Fm175xxReturnVal()
        result.err_code = Constants.FM175XX_OK
        result.out_data = [0x00, 0x04, 0x04, 0x02, 0x01, 0x00, self.version_storage, 0x03]
        return result

    def activate(self):
        return self.activate_status, list(self.uid), [0x44, 0x00], [], list(self.sak)

    def read_pages(self, page: int) -> Fm175xxReturnVal:
        self.read_calls.append(page)
        result = Fm175xxReturnVal()
        if page in self.read_fail_pages:
            result.err_code = Constants.FM175XX_CARD_READ_ERR
            return result
        result.err_code = Constants.FM175XX_OK
        offset = page * 4
        result.out_data = list(self.memory[offset:offset + 16])
        return result

    def write_page(self, page: int, data: list[int]) -> int:
        raw = bytes(data)
        self.write_calls.append((page, raw))
        if page in self.write_fail_pages:
            return Constants.FM175XX_CARD_WRITE_ERR
        if page not in self.ignore_write_pages:
            offset = page * 4
            self.memory[offset:offset + 4] = raw
        return Constants.FM175XX_OK

    def owned_region(self) -> bytes:
        start = 4 * 4
        return bytes(self.memory[start:start + TIGERTAG_OWNED_LENGTH])


def test_write_invalidates_header_writes_body_then_publishes_header() -> None:
    harness = _FmHarness()
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)

    assert result == {
        "ok": True,
        "code": "written",
        "uid": UID.hex().upper(),
        "previous_format": "maker",
        "start_page": 4,
        "end_page": 23,
        "bytes_written": 80,
        "verified": True,
        "tag_model": "NTAG215",
    }
    assert harness.owned_region() == MAKER_PAYLOAD
    assert harness.write_calls[0] == (4, b"\x00" * 4)
    assert [page for page, _data in harness.write_calls[1:20]] == list(range(5, 24))
    assert harness.write_calls[-1] == (4, MAKER_PAYLOAD[:4])
    assert harness.read_calls == [4, 8, 12, 16, 20, 2, 130] + [4, 8, 12, 16, 20] * 2


def test_init_tag_is_an_allowed_existing_format() -> None:
    harness = _FmHarness(TIGERTAG_INIT_ID)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["ok"] is True
    assert result["previous_format"] == "init"


def test_unrecognized_tag_requires_explicit_override() -> None:
    harness = _FmHarness(0)
    rejected = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert rejected["code"] == "unrecognized_tag"
    assert harness.write_calls == []

    allowed = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD, allow_unrecognized=True)
    assert allowed["ok"] is True
    assert allowed["previous_format"] == "unrecognized"


def test_tigertag_plus_is_never_overwritten_even_with_override() -> None:
    harness = _FmHarness(TIGERTAG_PLUS_ID, existing_product=1234)
    result = harness.reader.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        allow_unrecognized=True,
    )
    assert result["code"] == "protected_tag_format"
    assert harness.write_calls == []


def test_legacy_plus_product_zero_requires_explicit_upgrade_override() -> None:
    harness = _FmHarness(TIGERTAG_PLUS_ID, existing_product=0)
    rejected = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert rejected["code"] == "legacy_upgrade_required"
    assert harness.write_calls == []

    still_rejected = harness.reader.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        allow_unrecognized=True,
    )
    assert still_rejected["code"] == "legacy_upgrade_required"
    assert harness.write_calls == []

    upgraded = harness.reader.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        allow_legacy_migration=True,
    )
    assert upgraded["ok"] is True
    assert upgraded["previous_format"] == "legacy_openrfid_v1"
    assert harness.owned_region() == MAKER_PAYLOAD


def test_plus_product_zero_with_nonzero_legacy_signature_prefix_is_protected() -> None:
    harness = _FmHarness(TIGERTAG_PLUS_ID, existing_product=0)
    harness.memory[24 * 4] = 0x01
    result = harness.reader.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        allow_legacy_migration=True,
    )
    assert result["code"] == "protected_tag_format"
    assert harness.write_calls == []


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        (lambda harness: setattr(harness, "activate_status", Constants.FM175XX_CARD_ACTIVATE_ERR), "tag_not_present"),
        (lambda harness: setattr(harness, "sak", b"\x08"), "wrong_tag_type"),
        (lambda harness: setattr(harness, "uid", bytes.fromhex("04AABBCCDDEEFF")), "uid_mismatch"),
    ],
)
def test_activation_guards_run_before_any_memory_access(mutation, expected_code: str) -> None:
    harness = _FmHarness()
    mutation(harness)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == expected_code
    assert harness.read_calls == []
    assert harness.write_calls == []


def test_capacity_is_probed_through_page_23_before_header_invalidation() -> None:
    harness = _FmHarness()
    harness.read_fail_pages.add(20)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "capacity_probe_failed"
    assert result["page"] == 20
    assert harness.write_calls == []


@pytest.mark.parametrize(
    ("lock_byte_offset", "lock_mask", "expected_pages"),
    [
        (2 * 4 + 2, 1 << 4, [4]),
        (2 * 4 + 2, 1 << 7, [7]),
        (2 * 4 + 3, 1 << 0, [8]),
        (2 * 4 + 3, 1 << 7, [15]),
    ],
)
def test_static_locks_are_rejected_before_header_invalidation(
    lock_byte_offset, lock_mask, expected_pages
) -> None:
    harness = _FmHarness()
    harness.memory[lock_byte_offset] = lock_mask
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "tag_locked"
    assert result["lock_source"] == "static"
    assert result["locked_pages"] == expected_pages
    assert harness.write_calls == []


@pytest.mark.parametrize(
    ("storage", "lock_page", "lock_mask", "expected_pages"),
    [
        (0x0F, 40, 1 << 0, [16, 17]),
        (0x0F, 40, 1 << 3, [22, 23]),
        (0x11, 130, 1 << 0, list(range(16, 24))),
        (0x13, 226, 1 << 0, list(range(16, 24))),
    ],
)
def test_dynamic_locks_are_rejected_before_header_invalidation(
    storage, lock_page, lock_mask, expected_pages
) -> None:
    harness = _FmHarness()
    harness.version_storage = storage
    harness.memory[lock_page * 4] = lock_mask
    harness.memory[(lock_page + 1) * 4 + 3] = 0xFF
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "tag_locked"
    assert result["lock_source"] == "dynamic"
    assert result["locked_pages"] == expected_pages
    assert harness.write_calls == []


def test_password_protected_owned_region_is_rejected_before_mutation() -> None:
    harness = _FmHarness()
    harness.memory[(130 + 1) * 4 + 3] = 12
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "tag_password_protected"
    assert result["auth0_page"] == 12
    assert harness.write_calls == []


def test_unknown_ntag_version_is_rejected_before_mutation() -> None:
    harness = _FmHarness()
    harness.version_storage = 0x99
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "unsupported_tag_model"
    assert harness.write_calls == []


def test_authoritative_safety_check_runs_after_probe_before_first_write() -> None:
    harness = _FmHarness()
    result = harness.reader.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        safety_check=lambda: {
            "ok": False,
            "code": "print_active",
            "error": "print started while the operation was pending",
            "print_state": "printing",
        },
    )

    assert result["code"] == "print_active"
    assert result["phase"] == "pre_write"
    assert harness.read_calls == [4, 8, 12, 16, 20, 2, 130]
    assert harness.write_calls == []


def test_body_write_failure_leaves_header_invalidated() -> None:
    harness = _FmHarness()
    harness.write_fail_pages.add(9)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "body_write_failed"
    assert result["page"] == 9
    assert result["header_invalidated"] is True
    assert harness.owned_region()[:4] == b"\x00" * 4
    assert harness.write_calls[-1][0] == 9


def test_body_is_verified_before_header_is_published() -> None:
    harness = _FmHarness()
    harness.ignore_write_pages.add(6)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "body_verify_failed"
    assert result["header_invalidated"] is True
    assert harness.owned_region()[:4] == b"\x00" * 4
    assert harness.write_calls[-1][0] == 23


def test_full_readback_detects_final_header_mismatch() -> None:
    harness = _FmHarness(TIGERTAG_INIT_ID)
    harness.ignore_write_pages.add(4)
    result = harness.reader.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "verify_failed"
    assert harness.owned_region()[:4] == TIGERTAG_INIT_ID.to_bytes(4, "big")


def test_clear_zeros_exactly_the_owned_80_bytes_and_verifies() -> None:
    harness = _FmHarness()
    start = 4 * 4
    harness.memory[start:start + 80] = MAKER_PAYLOAD
    sentinel_before = bytes(harness.memory[:start])
    sentinel_after = bytes(harness.memory[start + 80:])

    result = harness.reader.clear_tigertag_maker(UID)

    assert result["code"] == "cleared"
    assert result["bytes_written"] == 80
    assert harness.owned_region() == b"\x00" * 80
    assert bytes(harness.memory[:start]) == sentinel_before
    assert bytes(harness.memory[start + 80:]) == sentinel_after
    assert harness.write_calls[0] == (4, b"\x00" * 4)
    assert harness.write_calls[-1] == (4, b"\x00" * 4)


def test_general_page_writer_is_not_public() -> None:
    assert not hasattr(Fm175xx, "write_ntag_pages")
    assert not hasattr(GpioEnabledRfidReader, "write_ntag_pages")


class _InnerSafeReader:
    def __init__(self):
        self.calls: list[tuple] = []

    def write_tigertag_maker(
        self,
        expected_uid,
        data,
        allow_unrecognized=False,
        allow_legacy_migration=False,
    ):
        self.calls.append(
            ("write", expected_uid, data, allow_unrecognized, allow_legacy_migration)
        )
        return {"ok": True, "code": "written"}

    def clear_tigertag_maker(
        self,
        expected_uid,
        allow_unrecognized=False,
        allow_legacy_migration=False,
    ):
        self.calls.append(
            ("clear", expected_uid, allow_unrecognized, allow_legacy_migration)
        )
        return {"ok": True, "code": "cleared"}


def test_gpio_wrapper_requires_an_ultralight_inner_reader() -> None:
    wrapper = object.__new__(GpioEnabledRfidReader)
    wrapper.rfid_reader = _InnerSafeReader()
    result = wrapper.write_tigertag_maker(UID, MAKER_PAYLOAD)
    assert result["code"] == "reader_not_supported"


class _InnerUltralightReader(MifareUltralightReader):
    def start_session(self):
        raise AssertionError("GPIO wrapper must not open a second inner session")

    def end_session(self):
        raise AssertionError("GPIO wrapper must not close a second inner session")

    def scan(self):
        return None

    def read_mifare_ultralight(self, scan_result):
        return None

    def write_tigertag_maker(
        self,
        expected_uid,
        data,
        allow_unrecognized=False,
        allow_legacy_migration=False,
    ):
        self.calls.append(
            ("write", expected_uid, data, allow_unrecognized, allow_legacy_migration)
        )
        return {"ok": True, "code": "written"}

    def clear_tigertag_maker(
        self,
        expected_uid,
        allow_unrecognized=False,
        allow_legacy_migration=False,
    ):
        self.calls.append(
            ("clear", expected_uid, allow_unrecognized, allow_legacy_migration)
        )
        return {"ok": True, "code": "cleared"}


def test_gpio_wrapper_delegates_without_opening_a_second_session() -> None:
    inner = object.__new__(_InnerUltralightReader)
    inner.calls = []
    wrapper = object.__new__(GpioEnabledRfidReader)
    wrapper.rfid_reader = inner

    written = wrapper.write_tigertag_maker(
        UID,
        MAKER_PAYLOAD,
        allow_unrecognized=True,
        allow_legacy_migration=True,
    )
    cleared = wrapper.clear_tigertag_maker(UID)

    assert written["code"] == "written"
    assert cleared["code"] == "cleared"
    assert inner.calls == [
        ("write", UID, MAKER_PAYLOAD, True, True),
        ("clear", UID, False, False),
    ]
