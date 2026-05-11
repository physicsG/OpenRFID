"""Tests for the Runtime NTAG pending-write queue.

The runtime serialises NTAG writes onto its read loop so the RFID bus is only
touched from one thread. ``submit_write`` blocks the caller on a
``threading.Event`` until the loop drains the request via
``_drain_pending_write``. These tests exercise that handshake without spinning
the full ``loop()`` (which is a ``while True``).
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from config import register_configurable_entity
from config.config_manager import LOADED_MODULES
from config.configuration import default_configuration
from runtime import Runtime


class _FakeReader:
    """Minimal stand-in for an ``RfidReader`` with NTAG write support."""

    def __init__(self, slot: int = 0, write_status: int = 0):
        self.name = f"fake_slot_{slot}"
        self.slot = slot
        self.last_read_uid = None
        self._write_status = write_status
        self.calls: list[tuple[int, bytes]] = []

    def write_ntag_pages(self, start_page: int, data: bytes) -> int:
        self.calls.append((start_page, bytes(data)))
        return self._write_status


class _FakeReaderNoWrite:
    def __init__(self, slot: int = 0):
        self.name = f"fake_slot_{slot}"
        self.slot = slot
        self.last_read_uid = None


@pytest.fixture(autouse=True)
def _reset_entities():
    LOADED_MODULES.clear()
    register_configurable_entity(default_configuration())
    yield
    LOADED_MODULES.clear()


def _build_runtime_with(reader) -> Runtime:
    runtime = Runtime()
    runtime.rfid_readers = [reader]
    runtime.read_retries_left = [0]
    return runtime


def test_submit_write_returns_ok_when_drained() -> None:
    reader = _FakeReader(slot=0, write_status=0)
    runtime = _build_runtime_with(reader)

    payload = b"\xDE\xAD\xBE\xEF" * 24  # 96 bytes (TigerTag-sized)

    result_box: dict = {}

    def _submit():
        result_box["result"] = runtime.submit_write(0, payload, start_page=4, timeout=2.0)

    submitter = threading.Thread(target=_submit, daemon=True)
    submitter.start()

    # Wait until the request is registered, then drain it from the "loop".
    deadline = time.time() + 1.0
    while time.time() < deadline:
        if 0 in runtime._pending_writes:
            break
        time.sleep(0.01)
    assert 0 in runtime._pending_writes, "submit_write did not register pending write"

    handled = runtime._drain_pending_write(0, reader)
    assert handled is True

    submitter.join(timeout=2.0)
    assert not submitter.is_alive(), "submitter did not unblock"

    result = result_box["result"]
    assert result["ok"] is True
    assert result["status"] == 0
    assert result["start_page"] == 4
    assert result["bytes_written"] == 96

    assert reader.calls == [(4, payload)]


def test_submit_write_rejects_invalid_slot() -> None:
    reader = _FakeReader(slot=0)
    runtime = _build_runtime_with(reader)
    result = runtime.submit_write(5, b"\x00" * 4)
    assert result["ok"] is False
    assert "invalid slot" in result["error"]


def test_submit_write_rejects_misaligned_data() -> None:
    reader = _FakeReader(slot=0)
    runtime = _build_runtime_with(reader)
    assert runtime.submit_write(0, b"\x00" * 5)["ok"] is False
    assert runtime.submit_write(0, b"")["ok"] is False


def test_submit_write_times_out_when_loop_idle() -> None:
    reader = _FakeReader(slot=0)
    runtime = _build_runtime_with(reader)

    result = runtime.submit_write(0, b"\x00" * 4, timeout=0.1)
    assert result["ok"] is False
    assert "timeout" in result["error"]
    # Pending entry must be cleared on timeout so next submit can register.
    assert 0 not in runtime._pending_writes


def test_drain_returns_false_when_no_pending() -> None:
    reader = _FakeReader(slot=0)
    runtime = _build_runtime_with(reader)
    assert runtime._drain_pending_write(0, reader) is False


def test_drain_handles_reader_without_write_support() -> None:
    reader = _FakeReaderNoWrite(slot=0)
    runtime = _build_runtime_with(reader)

    result_box: dict = {}

    def _submit():
        result_box["result"] = runtime.submit_write(0, b"\x00" * 4, timeout=2.0)

    submitter = threading.Thread(target=_submit, daemon=True)
    submitter.start()

    deadline = time.time() + 1.0
    while time.time() < deadline:
        if 0 in runtime._pending_writes:
            break
        time.sleep(0.01)

    handled = runtime._drain_pending_write(0, reader)
    assert handled is True

    submitter.join(timeout=2.0)
    result = result_box["result"]
    assert result["ok"] is False
    assert "does not support" in result["error"]
