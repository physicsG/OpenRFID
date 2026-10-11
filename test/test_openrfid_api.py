"""Contract tests for the guarded Moonraker OpenRFID agent API."""

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

from controllers.openrfid_api import OpenrfidApiController, tigertag_encoder


MAKER_PAYLOAD = bytes.fromhex("5BF59264") + (b"\x00" * 76)


class _Reader:
    name = "slot_0_reader"
    slot = 0


class _Runtime:
    def __init__(self):
        self.rfid_readers = [_Reader()]
        self.last_scans = {}
        self.started: list[int] = []
        self.write_calls: list[tuple] = []
        self.clear_calls: list[tuple] = []
        self.status_calls: list[str] = []
        self.shutting_down = False

    def is_shutting_down(self):
        return self.shutting_down

    def start_reading_tag(self, slot: int):
        self.started.append(slot)

    def get_tigertag_write_capabilities(self, slot: int) -> dict:
        return {
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
        }

    def submit_tigertag_write(
        self,
        slot,
        expected_uid,
        data,
        timeout=10.0,
        allow_unrecognized=False,
        allow_legacy_migration=False,
        safety_check=None,
    ):
        self.write_calls.append(
            (
                slot,
                expected_uid,
                data,
                timeout,
                allow_unrecognized,
                allow_legacy_migration,
            )
        )
        return {"ok": True, "code": "written", "verified": True}

    def submit_tigertag_clear(
        self,
        slot,
        expected_uid,
        timeout=10.0,
        allow_unrecognized=False,
        allow_legacy_migration=False,
        safety_check=None,
    ):
        self.clear_calls.append(
            (slot, expected_uid, timeout, allow_unrecognized, allow_legacy_migration)
        )
        return {"ok": True, "code": "cleared", "verified": True}

    def get_tigertag_operation_status(self, operation_id):
        self.status_calls.append(operation_id)
        return {
            "ok": True,
            "operation_id": operation_id,
            "operation_state": "completed",
            "completed": True,
            "result": {"ok": True, "code": "written"},
        }


def _controller(
    *,
    enabled=True,
    allow_unrecognized=False,
    allow_legacy_migration=False,
):
    controller = OpenrfidApiController({
        "__name": "openrfid_api",
        "moonraker_socket_path": "/tmp/moonraker.sock",
        "enable_write": str(enabled).lower(),
        "allow_unrecognized_write": str(allow_unrecognized).lower(),
        "allow_legacy_migration_write": str(allow_legacy_migration).lower(),
    })
    controller.runtime = _Runtime()
    return controller


@pytest.mark.parametrize(
    ("state", "expected_code"),
    [
        (None, "print_state_unknown"),
        ("printing", "print_active"),
        ("paused", "print_active"),
        ("starting", "print_state_unsafe"),
    ],
)
def test_write_gate_fails_closed(state, expected_code):
    controller = _controller()
    controller._set_print_state(state)
    result = controller._handle_write_tag({})
    assert result["ok"] is False
    assert result["code"] == expected_code


def test_write_gate_reports_disabled_before_printer_state():
    controller = _controller(enabled=False)
    result = controller._handle_write_tag({})
    assert result["code"] == "writes_disabled"


def test_write_gate_reports_service_stopping_before_other_state():
    controller = _controller(enabled=False)
    controller.runtime.shutting_down = True
    result = controller._handle_write_tag({})
    assert result["code"] == "service_stopping"


def test_list_channels_reports_hardware_and_guard_capabilities():
    controller = _controller()
    controller._set_print_state("standby")
    result = controller._handle_list_channels({})

    assert result["api_version"] == 2
    assert result["write_allowed"] is True
    assert result["print_state"] == "standby"
    assert result["capabilities"]["expected_format"] == "tigertag"
    assert result["capabilities"]["operation_status"] is True
    assert result["allow_legacy_migration_write"] is False
    assert result["channels"][0]["capabilities"]["tigertag_write"]["payload_bytes"] == 80


def test_extension_method_is_handled_without_klipper_remote_registration():
    controller = _controller()
    controller._set_print_state("standby")
    sent = []
    controller.send_message = sent.append

    # This is the direct request shape Moonraker relays for
    # server.extensions.request; no connection.register_remote_method call is
    # involved or required.
    controller.on_message({
        "jsonrpc": "2.0",
        "id": 17,
        "method": "openrfid/list_channels",
        "params": {},
    })
    assert sent[0]["id"] == 17
    assert sent[0]["result"]["api_version"] == 2


def test_connect_does_not_expose_extension_methods_to_klipper_gcode():
    controller = _controller()
    sent = []
    controller.send_message = sent.append
    controller.on_connect()
    methods = [message.get("method") for message in sent]
    assert "server.connection.identify" in methods
    assert "server.info" in methods
    assert "connection.register_remote_method" not in methods
    controller._stop_broadcast.set()


def test_write_uses_sdk_payload_and_safe_runtime(monkeypatch):
    controller = _controller()
    controller._set_print_state("standby")
    monkeypatch.setattr(tigertag_encoder, "encode", lambda spec: MAKER_PAYLOAD)
    monkeypatch.setattr(
        tigertag_encoder,
        "validate_maker_payload",
        lambda payload, uid=None: object(),
    )

    result = controller._handle_write_tag({
        "slot": 0,
        "expected_uid": "04:A1:B2:C3:D4:E5:F6",
        "expected_format": "tigertag",
        "spec": {"material": "PLA", "message": "work spool"},
        "timeout": 12,
    })

    assert result["ok"] is True
    assert result["verified"] is True
    assert result["tag_format"] == "tigertag"
    assert result["payload_bytes"] == 80
    assert controller.runtime.write_calls == [
        (0, "04A1B2C3D4E5F6", MAKER_PAYLOAD, 12.0, False, False)
    ]


def test_options_exposes_official_sdk_registries(monkeypatch):
    monkeypatch.setattr(tigertag_encoder, "get_options", lambda: {
        "schema_version": 1,
        "sdk": {"name": "tigertag", "version": "1.2.1", "commit": "abc"},
        "materials": [{"id": 38219, "label": "PLA"}],
        "brands": [],
        "aspects": [],
        "types": [],
        "diameters": [],
        "units": [],
    })
    result = _controller()._handle_tigertag_options({})
    assert result["ok"] is True
    assert result["schema_version"] == 1
    assert result["materials"] == [{"id": 38219, "label": "PLA"}]


def test_write_requires_expected_uid_and_format():
    controller = _controller()
    controller._set_print_state("standby")

    missing_uid = controller._handle_write_tag({
        "slot": 0,
        "expected_format": "tigertag",
        "spec": {},
    })
    assert missing_uid["code"] == "invalid_request"

    wrong_format = controller._handle_write_tag({
        "slot": 0,
        "expected_uid": "04A1B2C3D4E5F6",
        "expected_format": "openspool",
        "spec": {},
    })
    assert wrong_format["code"] == "invalid_request"


def test_unrecognized_override_requires_server_configuration():
    controller = _controller(allow_unrecognized=False)
    controller._set_print_state("standby")
    result = controller._handle_clear_tag({
        "slot": 0,
        "expected_uid": "04A1B2C3D4E5F6",
        "expected_format": "tigertag",
        "allow_unrecognized": True,
    })
    assert result["code"] == "invalid_request"


def test_clear_uses_fixed_safe_runtime_contract():
    controller = _controller(allow_unrecognized=True)
    controller._set_print_state("complete")
    result = controller._handle_clear_tag({
        "slot": 0,
        "expected_uid": "04A1B2C3D4E5F6",
        "expected_format": "tigertag",
        "allow_unrecognized": True,
        "timeout": 5,
    })

    assert result == {"ok": True, "code": "cleared", "verified": True}
    assert controller.runtime.clear_calls == [
        (0, "04A1B2C3D4E5F6", 5.0, True, False)
    ]


def test_legacy_migration_has_a_separate_server_and_request_opt_in():
    blocked = _controller(allow_unrecognized=True, allow_legacy_migration=False)
    blocked._set_print_state("standby")
    result = blocked._handle_clear_tag({
        "slot": 0,
        "expected_uid": "04A1B2C3D4E5F6",
        "expected_format": "tigertag",
        "allow_legacy_migration": True,
    })
    assert result["code"] == "invalid_request"

    allowed = _controller(allow_legacy_migration=True)
    allowed._set_print_state("standby")
    result = allowed._handle_clear_tag({
        "slot": 0,
        "expected_uid": "04A1B2C3D4E5F6",
        "expected_format": "tigertag",
        "allow_legacy_migration": True,
    })
    assert result["ok"] is True
    assert allowed.runtime.clear_calls == [
        (0, "04A1B2C3D4E5F6", 10.0, False, True)
    ]


def test_operation_status_recovers_terminal_result_without_write_gate():
    controller = _controller(enabled=False)
    result = controller._handle_operation_status({"operation_id": "op-123"})
    assert result["completed"] is True
    assert result["result"]["code"] == "written"
    assert controller.runtime.status_calls == ["op-123"]

    invalid = controller._handle_operation_status({"operation_id": "  "})
    assert invalid["code"] == "invalid_request"


def test_slot_validation_uses_logical_reader_slot_not_list_index():
    controller = _controller()
    controller.runtime.rfid_readers[0].slot = 7
    result = controller._handle_scan_slot({"slot": 7})
    assert result == {"ok": True, "slot": 7}
    assert controller.runtime.started == [7]


def test_status_subscription_updates_and_resets_authoritative_state():
    controller = _controller()
    sent = []
    controller.send_message = sent.append

    assert controller._handle_print_state_message({
        "id": 0x6F1A0100,
        "result": {"klippy_state": "ready"},
    }) is True
    assert sent[-1]["method"] == "printer.objects.subscribe"

    controller._handle_print_state_message({
        "id": 0x6F1A0101,
        "result": {"status": {"print_stats": {"state": "standby"}}},
    })
    assert controller._get_print_state()[0] == "standby"

    controller._handle_print_state_message({
        "method": "notify_status_update",
        "params": [{"print_stats": {"state": "printing"}}, 123.0],
    })
    assert controller._get_print_state()[0] == "printing"

    controller._handle_print_state_message({"method": "notify_klippy_disconnected"})
    assert controller._get_print_state()[0] is None


def test_extension_request_id_cannot_collide_with_internal_response_ids():
    controller = _controller()
    sent = []
    controller.send_message = sent.append

    controller.on_message({
        "jsonrpc": "2.0",
        "id": 0x6F1A0100,
        "method": "openrfid/list_channels",
        "params": {},
    })

    assert sent[0]["id"] == 0x6F1A0100
    assert sent[0]["result"]["api_version"] == 2


def test_pending_write_does_not_block_print_state_notifications(monkeypatch):
    controller = _controller()
    controller._set_print_state("standby")
    entered = threading.Event()
    release = threading.Event()
    responses = []

    def submit(_slot, _uid, _data, **kwargs):
        entered.set()
        assert release.wait(timeout=2.0)
        blocked = kwargs["safety_check"]()
        return blocked or {"ok": True, "code": "written"}

    controller.runtime.submit_tigertag_write = submit
    controller.send_message = responses.append
    monkeypatch.setattr(tigertag_encoder, "encode", lambda spec: MAKER_PAYLOAD)
    monkeypatch.setattr(
        tigertag_encoder,
        "validate_maker_payload",
        lambda payload, uid=None: object(),
    )

    controller.on_message({
        "jsonrpc": "2.0",
        "id": 91,
        "method": "openrfid/write_tag",
        "params": {
            "slot": 0,
            "expected_uid": "04A1B2C3D4E5F6",
            "expected_format": "tigertag",
            "spec": {"material": "PLA"},
        },
    })
    assert entered.wait(timeout=1.0)

    # This is handled on the receive thread while the operation worker waits.
    controller.on_message({
        "method": "notify_status_update",
        "params": [{"print_stats": {"state": "printing"}}, time.time()],
    })
    release.set()

    deadline = time.time() + 2.0
    while not responses and time.time() < deadline:
        time.sleep(0.01)
    assert responses
    assert responses[0]["id"] == 91
    assert responses[0]["result"]["code"] == "print_active"


def test_disconnect_while_write_is_queued_fails_prewrite_and_discards_stale_response(monkeypatch):
    controller = _controller()
    controller._set_print_state("standby")
    controller._connection_generation = 7
    controller._connection_connected = True
    controller.socket = object()
    entered = threading.Event()
    release = threading.Event()
    responses = []

    def submit(_slot, _uid, _data, **kwargs):
        entered.set()
        assert release.wait(timeout=2.0)
        return kwargs["safety_check"]() or {"ok": True, "code": "written"}

    def send(message, expected_generation=None):
        if expected_generation is not None and expected_generation != controller._connection_generation:
            return False
        responses.append(message)
        return True

    controller.runtime.submit_tigertag_write = submit
    controller.send_message = send
    monkeypatch.setattr(tigertag_encoder, "encode", lambda spec: MAKER_PAYLOAD)
    monkeypatch.setattr(
        tigertag_encoder,
        "validate_maker_payload",
        lambda payload, uid=None: object(),
    )

    controller.on_message({
        "jsonrpc": "2.0",
        "id": 92,
        "method": "openrfid/write_tag",
        "params": {
            "slot": 0,
            "expected_uid": "04A1B2C3D4E5F6",
            "expected_format": "tigertag",
            "spec": {"material": "PLA"},
        },
    })
    assert entered.wait(timeout=1.0)

    controller.on_disconnect()
    controller._connection_connected = False
    # Simulate a subsequent safe reconnect before the old worker wakes.
    controller._connection_generation = 8
    controller._connection_connected = True
    controller._set_print_state("standby")
    release.set()

    time.sleep(0.1)
    assert responses == []
