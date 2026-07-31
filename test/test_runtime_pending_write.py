"""Tests for Runtime's race-safe TigerTag operation queue."""

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

import runtime as runtime_module
from config import TYPE_RFID_READER, register_configurable_entity
from config.config_manager import LOADED_MODULES
from config.configuration import default_configuration
from reader.mifare_ultralight_reader import TIGERTAG_MAKER_ID, TIGERTAG_OWNED_LENGTH
from runtime import Runtime


UID = bytes.fromhex("04112233445566")
MAKER_PAYLOAD = TIGERTAG_MAKER_ID.to_bytes(4, "big") + bytes(range(TIGERTAG_OWNED_LENGTH - 4))


class _FakeReader:
    def __init__(self, slot: int = 0):
        self.name = f"fake_slot_{slot}"
        self.slot = slot
        self.enabled = True
        self.last_read_uid = None
        self.calls: list[tuple] = []
        self.sessions_started = 0
        self.sessions_ended = 0
        self.entered: threading.Event | None = None
        self.release: threading.Event | None = None

    def start_session(self) -> None:
        self.sessions_started += 1

    def end_session(self) -> None:
        self.sessions_ended += 1

    def write_tigertag_maker(
        self,
        expected_uid: bytes,
        data: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check=None,
    ) -> dict:
        self.calls.append(
            (
                "write",
                expected_uid,
                data,
                allow_unrecognized,
                allow_legacy_migration,
            )
        )
        if safety_check is not None:
            blocked = safety_check()
            if blocked is not None:
                return blocked
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(timeout=2.0)
        return {"ok": True, "code": "written", "bytes_written": len(data)}

    def clear_tigertag_maker(
        self,
        expected_uid: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check=None,
    ) -> dict:
        self.calls.append(
            ("clear", expected_uid, allow_unrecognized, allow_legacy_migration)
        )
        if safety_check is not None:
            blocked = safety_check()
            if blocked is not None:
                return blocked
        return {"ok": True, "code": "cleared", "bytes_written": TIGERTAG_OWNED_LENGTH}


class _FakeReaderNoWrite:
    def __init__(self, slot: int = 0):
        self.name = f"fake_slot_{slot}"
        self.slot = slot
        self.enabled = True
        self.last_read_uid = None


@pytest.fixture(autouse=True)
def _reset_entities():
    LOADED_MODULES.clear()
    register_configurable_entity(default_configuration())
    yield
    LOADED_MODULES.clear()


def _build_runtime_with(reader_or_readers) -> Runtime:
    runtime = Runtime()
    runtime.rfid_readers = (
        list(reader_or_readers)
        if isinstance(reader_or_readers, (list, tuple))
        else [reader_or_readers]
    )
    runtime._rebuild_reader_slot_mapping()
    runtime.read_retries_left = [0] * len(runtime.rfid_readers)
    return runtime


def _wait_until_queued(runtime: Runtime, slot: int = 0) -> None:
    deadline = time.time() + 1.0
    while time.time() < deadline:
        with runtime._pending_write_lock:
            if slot in runtime._pending_writes:
                return
        time.sleep(0.005)
    raise AssertionError(f"tag operation was not queued for slot {slot}")


def _run_clear_operation(runtime: Runtime, slot: int = 0) -> dict:
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_clear(slot, UID, timeout=2.0),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime, slot)
    assert runtime._drain_pending_write(slot) is True
    submitter.join(timeout=2.0)
    assert not submitter.is_alive()
    return result_box["result"]


def test_safe_write_returns_structured_result_when_drained() -> None:
    reader = _FakeReader()
    reader.last_read_uid = UID.hex()
    runtime = _build_runtime_with(reader)
    runtime.last_scans[0] = {"event": "tag_read", "uid": UID.hex().upper()}
    wakeups: list[int] = []
    original_start_reading_tag = runtime.start_reading_tag

    def _record_wakeup(slot: int) -> None:
        wakeups.append(slot)
        original_start_reading_tag(slot)

    runtime.start_reading_tag = _record_wakeup
    result_box: dict = {}

    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_write(
                0,
                UID.hex(":"),
                MAKER_PAYLOAD,
                timeout=2.0,
                allow_legacy_migration=True,
            ),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)

    assert runtime._drain_pending_write(0) is True
    submitter.join(timeout=2.0)

    result = result_box["result"]
    assert result["ok"] is True
    assert result["code"] == "written"
    assert result["action"] == "write"
    assert result["slot"] == 0
    assert result["expected_uid"] == UID.hex().upper()
    assert len(result["operation_id"]) == 32
    assert reader.calls == [("write", UID, MAKER_PAYLOAD, False, True)]
    assert reader.sessions_started == reader.sessions_ended == 1
    assert reader.last_read_uid is None
    assert 0 not in runtime.last_scans
    assert wakeups == [0, 0]
    assert runtime.read_retries_left[0] == runtime.config.read_retries


def test_safe_clear_uses_fixed_operation_and_allow_override() -> None:
    reader = _FakeReader()
    reader.last_read_uid = UID.hex()
    runtime = _build_runtime_with(reader)
    runtime.last_scans[0] = {"event": "tag_read", "uid": UID.hex().upper()}
    wakeups: list[int] = []
    original_start_reading_tag = runtime.start_reading_tag

    def _record_wakeup(slot: int) -> None:
        wakeups.append(slot)
        original_start_reading_tag(slot)

    runtime.start_reading_tag = _record_wakeup
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_clear(0, UID, timeout=2.0, allow_unrecognized=True),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)
    runtime._drain_pending_write(0)
    submitter.join(timeout=2.0)

    assert result_box["result"]["code"] == "cleared"
    assert reader.calls == [("clear", UID, True, False)]
    assert reader.last_read_uid is None
    assert 0 not in runtime.last_scans
    assert wakeups == [0, 0]


def test_runtime_propagates_late_safety_block_to_reader() -> None:
    reader = _FakeReader()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_write(
                0,
                UID,
                MAKER_PAYLOAD,
                timeout=2.0,
                safety_check=lambda: {
                    "ok": False,
                    "code": "print_active",
                    "error": "print started",
                },
            ),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)
    runtime._drain_pending_write(0)
    submitter.join(timeout=2.0)

    assert result_box["result"]["code"] == "print_active"
    assert result_box["result"]["action"] == "write"
    assert reader.sessions_started == reader.sessions_ended == 1


@pytest.mark.parametrize(
    ("call", "code"),
    [
        (lambda runtime: runtime.submit_tigertag_write(5, UID, MAKER_PAYLOAD), "invalid_slot"),
        (lambda runtime: runtime.submit_tigertag_write(0, "not-hex", MAKER_PAYLOAD), "invalid_uid"),
        (lambda runtime: runtime.submit_tigertag_write(0, b"\x01\x02", MAKER_PAYLOAD), "invalid_uid"),
        (lambda runtime: runtime.submit_tigertag_write(0, UID, b"\x00" * 79), "invalid_payload_length"),
        (lambda runtime: runtime.submit_tigertag_write(0, UID, b"\x00" * 80), "invalid_payload_header"),
        (lambda runtime: runtime.submit_tigertag_clear(0, UID, timeout=0), "invalid_timeout"),
        (
            lambda runtime: runtime.submit_tigertag_clear(0, UID, allow_unrecognized="false"),
            "invalid_allow_unrecognized",
        ),
        (
            lambda runtime: runtime.submit_tigertag_clear(
                0,
                UID,
                allow_legacy_migration="false",
            ),
            "invalid_allow_legacy_migration",
        ),
        (
            lambda runtime: runtime.submit_tigertag_clear(0, UID, safety_check="not-callable"),
            "invalid_safety_check",
        ),
    ],
)
def test_safe_operation_validation(call, code: str) -> None:
    runtime = _build_runtime_with(_FakeReader())
    result = call(runtime)
    assert result["ok"] is False
    assert result["code"] == code
    assert runtime._pending_writes == {}


def test_per_slot_busy_rejects_second_operation() -> None:
    reader = _FakeReader()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result", runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD, timeout=2.0)
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)

    busy = runtime.submit_tigertag_clear(0, UID, timeout=1.0)
    assert busy["code"] == "slot_busy"
    assert len(busy["active_operation_id"]) == 32
    assert busy["active_state"] == "queued"

    runtime._drain_pending_write(0)
    submitter.join(timeout=2.0)
    assert result_box["result"]["ok"] is True


def test_queued_timeout_cancels_only_that_operation() -> None:
    runtime = _build_runtime_with(_FakeReader())
    result = runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD, timeout=0.03)
    assert result["code"] == "timeout"
    assert 0 not in runtime._pending_writes
    assert runtime._drain_pending_write(0) is False
    status = runtime.get_tigertag_operation_status(result["operation_id"])
    assert status["operation_state"] == "cancelled"
    assert status["completed"] is True
    assert status["result"]["code"] == "timeout"


def test_queue_wakeup_failure_removes_exact_pending_operation() -> None:
    runtime = _build_runtime_with(_FakeReader())

    def _fail_wakeup(_slot: int) -> None:
        raise RuntimeError("wake failed")

    runtime.start_reading_tag = _fail_wakeup
    result = runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD)
    assert result["code"] == "queue_wakeup_failed"
    assert len(result["operation_id"]) == 32
    assert runtime._pending_writes == {}


def test_running_timeout_stays_registered_and_busy_until_completion() -> None:
    reader = _FakeReader()
    reader.entered = threading.Event()
    reader.release = threading.Event()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}

    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result", runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD, timeout=0.08)
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)
    drainer = threading.Thread(target=runtime._drain_pending_write, args=(0,), daemon=True)
    drainer.start()
    assert reader.entered.wait(timeout=1.0)

    submitter.join(timeout=1.0)
    timed_out = result_box["result"]
    assert timed_out["code"] == "timeout_in_progress"
    active_status = runtime.get_tigertag_operation_status(timed_out["operation_id"])
    assert active_status["ok"] is True
    assert active_status["operation_state"] == "running"
    assert active_status["completed"] is False
    assert active_status["slot"] == 0
    assert active_status["action"] == "write"
    assert active_status["started_at"] is not None
    with runtime._pending_write_lock:
        running = runtime._pending_writes[0]
        assert running.operation_id == timed_out["operation_id"]
        assert running.state == "running"

    busy = runtime.submit_tigertag_clear(0, UID, timeout=0.1)
    assert busy["code"] == "slot_busy"
    assert busy["active_operation_id"] == timed_out["operation_id"]

    reader.release.set()
    drainer.join(timeout=2.0)
    assert not drainer.is_alive()
    assert 0 not in runtime._pending_writes
    assert reader.sessions_started == reader.sessions_ended == 1
    completed_status = runtime.get_tigertag_operation_status(timed_out["operation_id"])
    assert completed_status["ok"] is True
    assert completed_status["operation_state"] == "completed"
    assert completed_status["completed"] is True
    assert completed_status["result"]["code"] == "written"
    assert completed_status["completed_at"] >= completed_status["started_at"]


def test_operation_status_history_is_bounded_and_returns_copies() -> None:
    runtime = _build_runtime_with(_FakeReader())
    runtime._tigertag_operation_history_limit = 2

    results = [_run_clear_operation(runtime) for _ in range(3)]

    assert (
        runtime.get_tigertag_operation_status(results[0]["operation_id"])["code"]
        == "operation_not_found"
    )
    retained = runtime.get_tigertag_operation_status(results[1]["operation_id"])
    assert retained["operation_state"] == "completed"
    assert retained["result"]["code"] == "cleared"

    retained["result"]["code"] = "mutated"
    assert (
        runtime.get_tigertag_operation_status(results[1]["operation_id"])["result"]["code"]
        == "cleared"
    )
    assert runtime.get_tigertag_operation_status("")["code"] == "invalid_operation_id"
    assert runtime.get_tigertag_operation_status("missing")["code"] == "operation_not_found"


def test_drain_handles_reader_without_safe_write_support() -> None:
    reader = _FakeReaderNoWrite()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result", runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD, timeout=2.0)
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)
    assert runtime._drain_pending_write(0) is True
    submitter.join(timeout=2.0)
    assert result_box["result"]["code"] == "reader_not_supported"


def test_capability_helper_reports_fixed_contract_and_busy_state() -> None:
    runtime = _build_runtime_with(_FakeReader())
    capabilities = runtime.get_tigertag_write_capabilities(0)
    assert capabilities == {
        "supported": True,
        "format": "tigertag",
        "variant": "maker",
        "expected_uid_required": True,
        "payload_bytes": 80,
        "start_page": 4,
        "end_page": 23,
        "clear_supported": True,
        "allow_unrecognized_supported": True,
        "allow_legacy_migration_supported": True,
        "busy": False,
        "active_operation_id": None,
        "active_state": None,
        "service_stopping": False,
    }
    assert runtime.get_tigertag_write_capabilities(3)["code"] == "invalid_slot"


def test_logical_slots_map_to_the_correct_reader_and_retry_index() -> None:
    slot_three_reader = _FakeReader(slot=3)
    slot_one_reader = _FakeReaderNoWrite(slot=1)
    runtime = _build_runtime_with([slot_three_reader, slot_one_reader])

    assert runtime.get_tigertag_write_capabilities(3)["supported"] is True
    assert runtime.get_tigertag_write_capabilities(1)["supported"] is False
    assert runtime.get_tigertag_write_capabilities(0)["code"] == "invalid_slot"

    runtime.start_reading_tag(1)
    assert runtime.read_retries_left == [0, runtime.config.read_retries]

    result = _run_clear_operation(runtime, slot=3)
    assert result["slot"] == 3
    assert slot_three_reader.calls == [("clear", UID, False, False)]
    assert runtime.read_retries_left == [
        runtime.config.read_retries,
        runtime.config.read_retries,
    ]


def test_runtime_initialization_rejects_duplicate_logical_slots(monkeypatch) -> None:
    readers = [_FakeReader(slot=2), _FakeReader(slot=2)]
    original_get_entities = runtime_module.get_entities_by_type

    def _get_entities(entity_type: str):
        if entity_type == TYPE_RFID_READER:
            return readers
        return original_get_entities(entity_type)

    monkeypatch.setattr(runtime_module, "get_entities_by_type", _get_entities)
    with pytest.raises(ValueError, match="duplicate RFID reader slot 2"):
        Runtime()


def test_shutdown_rejects_new_operations_before_reader_access() -> None:
    reader = _FakeReader()
    runtime = _build_runtime_with(reader)

    runtime.request_shutdown()
    result = runtime.submit_tigertag_clear(0, UID)

    assert runtime.is_shutting_down() is True
    assert result["code"] == "service_stopping"
    assert reader.calls == []
    assert runtime._pending_writes == {}


def test_shutdown_cancels_queued_operation_and_wakes_submitter() -> None:
    reader = _FakeReader()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_clear(0, UID, timeout=2.0),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)

    runtime.request_shutdown()
    runtime.loop()
    submitter.join(timeout=1.0)

    assert not submitter.is_alive()
    result = result_box["result"]
    assert result["code"] == "service_stopping"
    assert reader.calls == []
    status = runtime.get_tigertag_operation_status(result["operation_id"])
    assert status["operation_state"] == "cancelled"
    assert status["result"]["code"] == "service_stopping"


def test_shutdown_after_mutation_starts_allows_operation_cleanup_to_finish() -> None:
    reader = _FakeReader()
    reader.entered = threading.Event()
    reader.release = threading.Event()
    runtime = _build_runtime_with(reader)
    result_box: dict = {}
    submitter = threading.Thread(
        target=lambda: result_box.setdefault(
            "result",
            runtime.submit_tigertag_write(0, UID, MAKER_PAYLOAD, timeout=2.0),
        ),
        daemon=True,
    )
    submitter.start()
    _wait_until_queued(runtime)
    drainer = threading.Thread(
        target=runtime._drain_pending_write,
        args=(0,),
        daemon=True,
    )
    drainer.start()
    assert reader.entered.wait(timeout=1.0)

    runtime.request_shutdown()
    assert drainer.is_alive()
    reader.release.set()
    drainer.join(timeout=1.0)
    submitter.join(timeout=1.0)

    assert not drainer.is_alive()
    assert not submitter.is_alive()
    assert result_box["result"]["code"] == "written"
    assert reader.sessions_started == reader.sessions_ended == 1
    assert runtime.read_retries_left == [0]


def test_shutdown_finishes_running_slot_and_cancels_other_queued_slot() -> None:
    running_reader = _FakeReader(slot=3)
    running_reader.entered = threading.Event()
    running_reader.release = threading.Event()
    queued_reader = _FakeReader(slot=7)
    runtime = _build_runtime_with([running_reader, queued_reader])
    results: dict[int, dict] = {}

    def submit(slot: int) -> None:
        results[slot] = runtime.submit_tigertag_write(
            slot,
            UID,
            MAKER_PAYLOAD,
            timeout=2.0,
        )

    submitters = [
        threading.Thread(target=submit, args=(slot,), daemon=True)
        for slot in (3, 7)
    ]
    for thread in submitters:
        thread.start()
    _wait_until_queued(runtime, 3)
    _wait_until_queued(runtime, 7)

    drainer = threading.Thread(
        target=runtime._drain_pending_write,
        args=(3,),
        daemon=True,
    )
    drainer.start()
    assert running_reader.entered.wait(timeout=1.0)
    runtime.request_shutdown()
    assert runtime._drain_pending_write(7) is True

    running_reader.release.set()
    drainer.join(timeout=1.0)
    for thread in submitters:
        thread.join(timeout=1.0)

    assert results[3]["code"] == "written"
    assert results[7]["code"] == "service_stopping"
    assert len(running_reader.calls) == 1
    assert queued_reader.calls == []


def test_shutdown_during_preflight_fails_before_fake_mutation() -> None:
    reader = _FakeReader()
    runtime = _build_runtime_with(reader)
    original_start_session = reader.start_session

    def start_and_stop() -> None:
        original_start_session()
        runtime.request_shutdown()

    reader.start_session = start_and_stop
    result = _run_clear_operation(runtime)

    assert result["code"] == "service_stopping"
    assert reader.sessions_started == reader.sessions_ended == 1


def test_shutdown_interrupts_long_idle_wait_promptly() -> None:
    runtime = _build_runtime_with(_FakeReader())
    runtime.config.read_interval_seconds = 30
    loop_thread = threading.Thread(target=runtime.loop, daemon=True)
    loop_thread.start()
    assert loop_thread.is_alive()

    started = time.monotonic()
    runtime.request_shutdown()
    loop_thread.join(timeout=0.5)

    assert not loop_thread.is_alive()
    assert time.monotonic() - started < 0.5
