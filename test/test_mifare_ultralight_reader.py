"""Exercise Type 2 memory boundaries through the real reader's READ command."""
import logging
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest
import yaml

from test_tags import (
    PROCESSOR_FIXTURES,
    _assert_expected_matches_actual,
    _collect_fixture_cases,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from reader.scan_result import ScanResult
from tag.tag_types import TagType


@pytest.fixture
def reader(monkeypatch):
    # The RF command is simulated; no Linux GPIO/SPI hardware is accessed.
    monkeypatch.setitem(sys.modules, "gpiod", ModuleType("gpiod"))
    monkeypatch.setitem(sys.modules, "spidev", ModuleType("spidev"))
    from reader.fm175xx.rfid import Fm175xx

    instance = Fm175xx.__new__(Fm175xx)
    instance.logger = logging.getLogger("test.ultralight")
    return instance


@pytest.fixture
def scan():
    return ScanResult(TagType.MifareUltralight, b"\x04\x01\x02\x03\x04\x05\x06", b"\x00\x44", b"\x00", b"\x04\x00")


def memory(size_byte):
    physical_sizes = {0x06: 64, 0x12: 180, 0x3E: 540, 0x6D: 924}
    data = bytearray(i % 251 for i in range(physical_sizes[size_byte]))
    data[12:16] = bytes([0xE1, 0x10, size_byte, 0x00])
    return bytes(data)


def mock_tag(reader, monkeypatch, data, failures=None, short_page=None):
    from reader.fm175xx import constants
    from reader.fm175xx.rfid import Fm175xxReturnVal

    failures = dict(failures or {})

    def execute(cmd):
        assert cmd.send_buff[0] == 0x30
        assert cmd.bytes_to_recv == 16
        page = cmd.send_buff[1]
        assert 0 <= page <= 255
        offset = page * 4
        assert offset + 16 <= len(data), "READ crossed the physical memory boundary"
        result = Fm175xxReturnVal()
        if failures.get(page, 0):
            failures[page] -= 1
            result.err_code = constants.FM175XX_CARD_TIMER_ERR
        else:
            result.err_code = constants.FM175XX_OK
            result.out_data = list(data[offset:offset + 16])
            if page == short_page:
                result.out_data.pop()
        return result

    command = Mock(side_effect=execute)
    monkeypatch.setattr(reader, "_Fm175xx__command_exe", command)
    return command


@pytest.mark.parametrize("size_byte,total_size,last_page", [
    pytest.param(0x06, 64, 12, id="ultralight"),
    pytest.param(0x12, 180, 41, id="ntag213"),
    pytest.param(0x3E, 540, 131, id="ntag215"),
    pytest.param(0x6D, 924, 227, id="ntag216"),
])
def test_reads_all_physical_pages(reader, scan, monkeypatch, size_byte, total_size, last_page):
    data = memory(size_byte)
    command = mock_tag(reader, monkeypatch, data)

    result = reader.read_mifare_ultralight(scan)

    assert result == data
    assert len(result) == total_size
    assert command.call_args_list[0].args[0].send_buff == [0x30, 0]
    assert command.call_args_list[-1].args[0].send_buff == [0x30, last_page]
    assert command.call_count == (total_size + 15) // 16
    assert sum(call.args[0].send_buff[1] == 0 for call in command.call_args_list) == 1


@pytest.mark.parametrize("cc", [
    bytes.fromhex("00 00 00 00"),
    bytes.fromhex("00 10 12 00"),
    bytes.fromhex("e1 10 00 00"),
    bytes.fromhex("e1 10 01 00"),
    bytes.fromhex("e1 10 7f 00"),
    bytes.fromhex("e1 10 ff 00"),
])
def test_invalid_cc_fails_before_reading_data(reader, scan, monkeypatch, cc):
    data = bytearray(memory(0x12))
    data[12:16] = cc
    command = mock_tag(reader, monkeypatch, data)

    assert reader.read_mifare_ultralight(scan) is None
    assert command.call_count == 1


@pytest.mark.parametrize("size_byte,page", [
    (0x6D, 0), (0x6D, 4), (0x6D, 48), (0x6D, 132),
    (0x06, 12), (0x12, 41), (0x3E, 131), (0x6D, 227),
])
def test_persistent_read_failure_never_returns_partial_success(reader, scan, monkeypatch, size_byte, page):
    # Page 48 used to be accepted as a successful end after three failed reads.
    command = mock_tag(reader, monkeypatch, memory(size_byte), failures={page: 3})

    assert reader.read_mifare_ultralight(scan) is None
    assert [call.args[0].send_buff[1] for call in command.call_args_list[-3:]] == [page] * 3


@pytest.mark.parametrize("page", [0, 4, 227])
def test_transient_failure_retries_and_returns_complete_data(reader, scan, monkeypatch, page):
    data = memory(0x6D)
    command = mock_tag(reader, monkeypatch, data, failures={page: 2})

    assert reader.read_mifare_ultralight(scan) == data
    assert sum(call.args[0].send_buff[1] == page for call in command.call_args_list) == 3


@pytest.mark.parametrize("page", [0, 4])
def test_short_response_is_a_read_failure(reader, scan, monkeypatch, page):
    mock_tag(reader, monkeypatch, memory(0x12), short_page=page)

    assert reader.read_mifare_ultralight(scan) is None


@pytest.mark.parametrize("fixture_path", [
    path for path in _collect_fixture_cases()
    if PROCESSOR_FIXTURES[path.parent.name]["tag_type"] == TagType.MifareUltralight
], ids=lambda path: path.stem)
def test_physical_dump_preserves_processor_output(reader, scan, monkeypatch, fixture_path):
    data = fixture_path.read_bytes()
    # Some older NTAG213 dumps include rollover bytes. Simulate only physical
    # memory and pass the real reader's exact-length output to each processor.
    physical_sizes = {0x06: 64, 0x12: 180, 0x3E: 540, 0x6D: 924}
    physical_size = physical_sizes[data[14]]
    assert len(data) >= physical_size
    mock_tag(reader, monkeypatch, data[:physical_size])

    dump = reader.read_mifare_ultralight(scan)
    assert dump == data[:physical_size]
    processor = PROCESSOR_FIXTURES[fixture_path.parent.name]["build_processor"]()
    filament = processor.process_tag(scan, dump)

    assert filament is not None
    expected = yaml.safe_load(fixture_path.with_suffix(".yml").read_text(encoding="utf-8"))
    _assert_expected_matches_actual(expected, filament.to_dict())
