"""Moonraker agent controller exposing OpenRFID over JSON-RPC.

Registers a Moonraker *agent* named ``openrfid`` that:

* exposes the remote methods ``openrfid/list_channels``, ``openrfid/scan_slot``,
  ``openrfid/write_tag``, ``openrfid/clear_tag``, ``openrfid/tigertag_encode``
  ``openrfid/tigertag_options``, and ``openrfid/operation_status``,
* broadcasts ``notify_agent_event`` notifications (event name
  ``openrfid/scan``) for every scan event picked up from a configured
  :class:`exporters.openrfid_agent_event.OpenrfidAgentEventExporter`.

Write operations (``write_tag`` / ``clear_tag``) are gated behind the
``enable_write`` config flag (default ``false``) so installations that don't
want write access stay safe by default.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable

from config import get_entities_by_type, TYPE_EXPORTER
from controllers.moonraker_controller import MoonrakerController
from exporters.openrfid_agent_event import OpenrfidAgentEventExporter
from runtime import Runtime
from tag.tigertag import encoder as tigertag_encoder


AGENT_NAME = "openrfid"

_MSG_ID_REGISTER_AGENT = 0x6F1A0001
_MSG_ID_SERVER_INFO = 0x6F1A0100
_MSG_ID_PRINT_STATE_SUBSCRIBE = 0x6F1A0101

_SAFE_PRINT_STATES = frozenset({"standby", "complete", "cancelled", "error"})
_ACTIVE_PRINT_STATES = frozenset({"printing", "paused"})

REMOTE_METHOD_LIST_CHANNELS = "openrfid/list_channels"
REMOTE_METHOD_SCAN_SLOT = "openrfid/scan_slot"
REMOTE_METHOD_WRITE_TAG = "openrfid/write_tag"
REMOTE_METHOD_CLEAR_TAG = "openrfid/clear_tag"
REMOTE_METHOD_TIGERTAG_ENCODE = "openrfid/tigertag_encode"
REMOTE_METHOD_TIGERTAG_OPTIONS = "openrfid/tigertag_options"
REMOTE_METHOD_OPERATION_STATUS = "openrfid/operation_status"

_ASYNC_REMOTE_METHODS = frozenset({
    REMOTE_METHOD_WRITE_TAG,
    REMOTE_METHOD_CLEAR_TAG,
})


class OpenrfidApiController(MoonrakerController):
    """Moonraker agent that surfaces OpenRFID to Mainsail/Fluidd-style UIs."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.runtime: Runtime
        self.enable_write = str(config.get("enable_write", "false")).lower() == "true"
        self.allow_unrecognized_write = (
            str(config.get("allow_unrecognized_write", "false")).lower() == "true"
        )
        self.allow_legacy_migration_write = (
            str(config.get("allow_legacy_migration_write", "false")).lower()
            == "true"
        )
        self.agent_event_exporter_name = config.get("agent_event_exporter", None)

        self._exporter: OpenrfidAgentEventExporter | None = None
        self._broadcast_thread: threading.Thread | None = None
        self._stop_broadcast = threading.Event()
        self._print_state_lock = threading.Lock()
        self._print_state: str | None = None
        self._print_state_updated_at: float | None = None
        self._klippy_ready = False

        self._handlers: dict[str, Callable[[dict], Any]] = {
            REMOTE_METHOD_LIST_CHANNELS: self._handle_list_channels,
            REMOTE_METHOD_SCAN_SLOT: self._handle_scan_slot,
            REMOTE_METHOD_WRITE_TAG: self._handle_write_tag,
            REMOTE_METHOD_CLEAR_TAG: self._handle_clear_tag,
            REMOTE_METHOD_TIGERTAG_ENCODE: self._handle_tigertag_encode,
            REMOTE_METHOD_TIGERTAG_OPTIONS: self._handle_tigertag_options,
            REMOTE_METHOD_OPERATION_STATUS: self._handle_operation_status,
        }

    # ------------------------------------------------------------------
    # Wiring helpers
    # ------------------------------------------------------------------
    def _resolve_exporter(self) -> OpenrfidAgentEventExporter | None:
        if self._exporter is not None:
            return self._exporter

        exporters = [e for e in get_entities_by_type(TYPE_EXPORTER) if isinstance(e, OpenrfidAgentEventExporter)]
        if not exporters:
            return None

        if self.agent_event_exporter_name:
            for e in exporters:
                if e.name == self.agent_event_exporter_name:
                    self._exporter = e
                    return e
            self.logger.warning("Configured agent_event_exporter '%s' not found", self.agent_event_exporter_name)
            return None

        if len(exporters) > 1:
            self.logger.warning(
                "Multiple openrfid_agent_event_exporter entities found; using '%s'",
                exporters[0].name,
            )
        self._exporter = exporters[0]
        return self._exporter

    # ------------------------------------------------------------------
    # MoonrakerController hooks
    # ------------------------------------------------------------------
    def on_connect(self):
        self._set_print_state(None)
        self._klippy_ready = False
        self._send_register_agent()

        # Start (or restart) the broadcast pump.
        self._stop_broadcast.set()
        if self._broadcast_thread and self._broadcast_thread.is_alive():
            self._broadcast_thread.join(timeout=1.0)
        self._stop_broadcast = threading.Event()
        self._broadcast_thread = threading.Thread(
            target=self._broadcast_loop,
            args=(self.current_connection_generation(),),
            name="openrfid-agent-broadcast",
            daemon=True,
        )
        self._broadcast_thread.start()

        # The write gate is based on Moonraker's authoritative print_stats
        # object. Until the initial subscription result arrives, writes fail
        # closed with ``print_state_unknown``.
        self._send_server_info_query()

    def on_disconnect(self):
        # Fail closed immediately during Moonraker's reconnect delay. A worker
        # also captures the socket generation, so a later reconnect cannot
        # make its stale safety decision or JSON-RPC response valid again.
        self._klippy_ready = False
        self._set_print_state(None)
        self._stop_broadcast.set()

    def on_message(self, message: dict):
        if self._handle_print_state_message(message):
            return

        method = message.get("method")
        if not method or method not in self._handlers:
            return

        msg_id = message.get("id")
        request_generation = self.current_connection_generation()
        params = message.get("params") or {}
        if isinstance(params, list):
            params = params[0] if params and isinstance(params[0], dict) else {}

        # A physical operation waits on Runtime's RFID-loop queue. Run it off
        # the Moonraker receive thread so print-state notifications continue
        # updating the authoritative cache while the request is pending.
        if method in _ASYNC_REMOTE_METHODS:
            threading.Thread(
                target=self._handle_remote_method,
                args=(method, params, msg_id, request_generation),
                name="openrfid-agent-operation",
                daemon=True,
            ).start()
            return

        self._handle_remote_method(method, params, msg_id, request_generation)

    def _handle_remote_method(
        self,
        method: str,
        params: dict,
        msg_id: Any,
        request_generation: int | None = None,
    ):
        """Execute one registered method and send its JSON-RPC response."""

        try:
            if method in _ASYNC_REMOTE_METHODS:
                result = self._handlers[method](params, request_generation)
            else:
                result = self._handlers[method](params)
            response: dict[str, Any] = {"jsonrpc": "2.0", "result": result}
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Handler for %s failed", method)
            response = {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(exc)}}

        if msg_id is not None:
            response["id"] = msg_id
            try:
                if request_generation is None:
                    self.send_message(response)
                elif not self.send_message(
                    response,
                    expected_generation=request_generation,
                ):
                    self.logger.info(
                        "Discarding stale response for %s after Moonraker reconnect",
                        method,
                    )
            except Exception:
                self.logger.exception("Failed to send response for %s", method)

    # ------------------------------------------------------------------
    # Outgoing messages
    # ------------------------------------------------------------------
    def _send_register_agent(self):
        self.send_message({
            "jsonrpc": "2.0",
            "method": "server.connection.identify",
            "params": {
                "client_name": AGENT_NAME,
                "version": "0.2.0",
                "type": "agent",
                "url": "https://github.com/physicsG/OpenRFID",
            },
            "id": _MSG_ID_REGISTER_AGENT,
        })

    def _send_server_info_query(self):
        self.send_message({
            "jsonrpc": "2.0",
            "method": "server.info",
            "id": _MSG_ID_SERVER_INFO,
        })

    def _send_print_state_subscribe(self):
        self.send_message({
            "jsonrpc": "2.0",
            "method": "printer.objects.subscribe",
            "params": {"objects": {"print_stats": ["state"]}},
            "id": _MSG_ID_PRINT_STATE_SUBSCRIBE,
        })

    def _set_print_state(self, state: Any):
        normalized = str(state).strip().lower() if state is not None else None
        if not normalized:
            normalized = None
        with self._print_state_lock:
            self._print_state = normalized
            self._print_state_updated_at = time.time() if normalized is not None else None

    def _get_print_state(self) -> tuple[str | None, float | None]:
        with self._print_state_lock:
            return self._print_state, self._print_state_updated_at

    @staticmethod
    def _status_objects(message: dict) -> dict:
        params = message.get("params") or {}
        if isinstance(params, list):
            params = params[0] if params and isinstance(params[0], dict) else {}
        return params if isinstance(params, dict) else {}

    def _handle_print_state_message(self, message: dict) -> bool:
        msg_id = message.get("id")
        # Moonraker extension callers choose their own JSON-RPC ids. Only a
        # response (no method) can satisfy one of our internal request ids.
        is_response = message.get("method") is None
        if is_response and msg_id == _MSG_ID_SERVER_INFO:
            info = message.get("result") or {}
            self._klippy_ready = info.get("klippy_state") == "ready"
            if self._klippy_ready:
                self._send_print_state_subscribe()
            else:
                self._set_print_state(None)
            return True

        if is_response and msg_id == _MSG_ID_PRINT_STATE_SUBSCRIBE:
            result = message.get("result") or {}
            state = (result.get("status") or {}).get("print_stats", {}).get("state")
            self._set_print_state(state)
            return True

        method = message.get("method")
        if method in ("notify_klippy_disconnected", "notify_klippy_shutdown"):
            self._klippy_ready = False
            self._set_print_state(None)
            return True
        if method == "notify_klippy_ready":
            self._klippy_ready = True
            self._set_print_state(None)
            self._send_print_state_subscribe()
            return True
        if method == "notify_status_update":
            objects = self._status_objects(message)
            state = (objects.get("print_stats") or {}).get("state")
            if state is not None:
                self._set_print_state(state)
            return True
        return False

    def _broadcast_loop(self, connection_generation: int | None = None):
        exporter = self._resolve_exporter()
        if exporter is None:
            self.logger.info("No openrfid_agent_event_exporter configured; agent events disabled")
            return

        while not self._stop_broadcast.is_set():
            event = exporter.pop_event(timeout=0.5)
            if event is None:
                continue
            try:
                # Per Moonraker's agent protocol, agents emit events via
                # `connection.send_event` with `{event, data}`. Moonraker
                # stamps the agent name from the connection identity and
                # rebroadcasts to subscribers as `notify_agent_event`
                # notifications. Sending `notify_agent_event` directly
                # is treated as an RPC call and rejected with -32601.
                # https://moonraker.readthedocs.io/en/latest/external_api/extensions/#send-an-agent-event
                sent = self.send_message({
                    "jsonrpc": "2.0",
                    "method": "connection.send_event",
                    "params": {
                        "event": "openrfid/scan",
                        "data": event,
                    },
                }, expected_generation=connection_generation)
                if not sent:
                    return
            except Exception:
                self.logger.exception("Failed to broadcast agent event; reconnect imminent")
                return

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------
    def _handle_list_channels(self, _params: dict) -> dict:
        channels = []
        for i, reader in enumerate(self.runtime.rfid_readers):
            slot = getattr(reader, "slot", i)
            try:
                write_capabilities = self.runtime.get_tigertag_write_capabilities(slot)
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.exception("Unable to inspect write capability for slot %s", slot)
                write_capabilities = {
                    "supported": False,
                    "format": "tigertag",
                    "variant": "maker",
                    "error": str(exc),
                }
            channels.append({
                "slot": slot,
                "name": reader.name,
                "last_scan": self.runtime.last_scans.get(slot),
                "capabilities": {
                    "scan": True,
                    "tigertag_write": write_capabilities,
                },
            })
        print_state, print_state_updated_at = self._get_print_state()
        block = self._write_block()
        return {
            "api_version": 2,
            "channels": channels,
            "write_enabled": self.enable_write,
            "write_allowed": block is None,
            "write_block": block,
            "allow_unrecognized_write": self.allow_unrecognized_write,
            "allow_legacy_migration_write": self.allow_legacy_migration_write,
            "print_state": print_state,
            "print_state_updated_at": print_state_updated_at,
            "capabilities": {
                "scan": True,
                "tigertag_encode": True,
                "tigertag_options": True,
                "tigertag_write": self.enable_write,
                "tigertag_clear": self.enable_write,
                "operation_status": True,
                "expected_uid_required": True,
                "expected_format": "tigertag",
                "print_state_guard": True,
            },
        }

    def _handle_scan_slot(self, params: dict) -> dict:
        try:
            slot = self._require_slot(params)
        except ValueError as exc:
            return self._error("invalid_request", str(exc))
        self.runtime.start_reading_tag(slot)
        return {"ok": True, "slot": slot}

    def _handle_write_tag(
        self,
        params: dict,
        request_generation: int | None = None,
    ) -> dict:
        blocked = self._write_block_for_generation(request_generation)
        if blocked is not None:
            return blocked
        try:
            slot = self._require_slot(params)
            expected_uid = self._require_expected_uid(params)
            self._require_expected_format(params)
            allow_unrecognized = self._allow_unrecognized(params)
            allow_legacy_migration = self._allow_legacy_migration(params)
            timeout = self._timeout(params)
        except ValueError as exc:
            return self._error("invalid_request", str(exc))

        spec = params.get("spec")
        if spec is not None:
            if not isinstance(spec, dict):
                return self._error("invalid_spec", "spec must be an object")
            try:
                data = tigertag_encoder.encode(spec)
            except (TypeError, ValueError) as exc:
                return self._error("invalid_spec", str(exc))
        else:
            data_hex = params.get("data_hex") or params.get("data")
            if not isinstance(data_hex, str):
                return self._error("missing_payload", "spec or data_hex is required")
            try:
                data = bytes.fromhex(data_hex)
            except ValueError as exc:
                return self._error("invalid_hex", f"invalid data_hex: {exc}")

        try:
            tigertag_encoder.validate_maker_payload(
                data,
                uid=bytes.fromhex(expected_uid),
            )
        except (TypeError, ValueError) as exc:
            return self._error("invalid_payload", str(exc))

        result = self.runtime.submit_tigertag_write(
            slot,
            expected_uid,
            data,
            timeout=timeout,
            allow_unrecognized=allow_unrecognized,
            allow_legacy_migration=allow_legacy_migration,
            safety_check=lambda: self._write_block_for_generation(request_generation),
        )
        if result.get("ok"):
            result = {
                **result,
                "tag_format": "tigertag",
                "tag_variant": "maker",
                "payload_bytes": len(data),
            }
        return result

    def _handle_clear_tag(
        self,
        params: dict,
        request_generation: int | None = None,
    ) -> dict:
        blocked = self._write_block_for_generation(request_generation)
        if blocked is not None:
            return blocked
        try:
            slot = self._require_slot(params)
            expected_uid = self._require_expected_uid(params)
            self._require_expected_format(params)
            timeout = self._timeout(params)
            allow_unrecognized = self._allow_unrecognized(params)
            allow_legacy_migration = self._allow_legacy_migration(params)
        except ValueError as exc:
            return self._error("invalid_request", str(exc))
        return self.runtime.submit_tigertag_clear(
            slot,
            expected_uid,
            timeout=timeout,
            allow_unrecognized=allow_unrecognized,
            allow_legacy_migration=allow_legacy_migration,
            safety_check=lambda: self._write_block_for_generation(request_generation),
        )

    def _handle_tigertag_encode(self, params: dict) -> dict:
        spec = params.get("spec") or {}
        if not isinstance(spec, dict):
            return {"ok": False, "error": "spec must be an object"}
        try:
            payload = tigertag_encoder.encode(spec)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {
            "ok": True,
            "tag_format": "tigertag",
            "tag_variant": "maker",
            "data_hex": payload.hex(),
            "start_page": tigertag_encoder.USER_DATA_START_PAGE,
            "end_page": tigertag_encoder.USER_DATA_END_PAGE,
            "bytes": len(payload),
            "pages": len(payload) // 4,
        }

    def _handle_tigertag_options(self, _params: dict) -> dict:
        try:
            options = tigertag_encoder.get_options()
        except Exception as exc:  # pragma: no cover - defensive SDK/database error
            self.logger.exception("Unable to load TigerTag authoring options")
            return self._error("options_unavailable", str(exc))
        return {"ok": True, **options}

    def _handle_operation_status(self, params: dict) -> dict:
        operation_id = params.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id.strip():
            return self._error(
                "invalid_request",
                "operation_id must be a non-empty string",
            )
        return self.runtime.get_tigertag_operation_status(operation_id.strip())

    @staticmethod
    def _error(code: str, error: str, **details: Any) -> dict[str, Any]:
        return {"ok": False, "code": code, "error": error, **details}

    def _write_block(self) -> dict[str, Any] | None:
        if self.runtime.is_shutting_down():
            return self._error(
                "service_stopping",
                "OpenRFID is stopping; refusing to start a tag operation",
            )
        if not self.enable_write:
            return self._error(
                "writes_disabled",
                "writes disabled (set enable_write = true in [openrfid_api])",
            )
        state, _updated_at = self._get_print_state()
        if state is None:
            return self._error(
                "print_state_unknown",
                "printer state is unavailable; refusing to write",
            )
        if state in _ACTIVE_PRINT_STATES:
            return self._error(
                "print_active",
                f"tag writes are blocked while print_stats.state is '{state}'",
                print_state=state,
            )
        if state not in _SAFE_PRINT_STATES:
            return self._error(
                "print_state_unsafe",
                f"tag writes are not allowed while print_stats.state is '{state}'",
                print_state=state,
            )
        return None

    def _write_block_for_generation(
        self,
        request_generation: int | None,
    ) -> dict[str, Any] | None:
        # Direct handler calls used by integrations/tests do not carry a
        # socket generation. Relayed Moonraker requests always do.
        if request_generation is not None and not self.is_connection_current(
            request_generation
        ):
            return self._error(
                "moonraker_connection_lost",
                "Moonraker connection changed while the tag operation was pending; refusing to write",
            )
        return self._write_block()

    def _require_slot(self, params: dict) -> int:
        slot = params.get("slot")
        if slot is None:
            raise ValueError("slot is required")
        try:
            normalized = int(slot)
        except (TypeError, ValueError) as exc:
            raise ValueError("slot must be an integer") from exc
        configured_slots = {
            getattr(reader, "slot", index)
            for index, reader in enumerate(self.runtime.rfid_readers)
        }
        if isinstance(slot, bool) or normalized < 0 or normalized not in configured_slots:
            raise ValueError(f"invalid slot {normalized}")
        return normalized

    @staticmethod
    def _require_expected_uid(params: dict) -> str:
        value = params.get("expected_uid")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("expected_uid is required")
        compact = value.strip()
        if compact.lower().startswith("0x"):
            compact = compact[2:]
        for separator in (" ", ":", "_", "-"):
            compact = compact.replace(separator, "")
        try:
            uid = bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError("expected_uid must be hexadecimal") from exc
        if len(uid) != 7:
            raise ValueError("expected_uid must contain the 7-byte NTAG UID")
        return uid.hex().upper()

    @staticmethod
    def _require_expected_format(params: dict):
        value = params.get("expected_format")
        if not isinstance(value, str) or value.strip().lower() != "tigertag":
            raise ValueError("expected_format must be 'tigertag'")

    def _allow_unrecognized(self, params: dict) -> bool:
        value = params.get("allow_unrecognized", False)
        if not isinstance(value, bool):
            raise ValueError("allow_unrecognized must be a boolean")
        if value and not self.allow_unrecognized_write:
            raise ValueError(
                "allow_unrecognized requires allow_unrecognized_write = true in [openrfid_api]"
            )
        return value

    def _allow_legacy_migration(self, params: dict) -> bool:
        value = params.get("allow_legacy_migration", False)
        if not isinstance(value, bool):
            raise ValueError("allow_legacy_migration must be a boolean")
        if value and not self.allow_legacy_migration_write:
            raise ValueError(
                "allow_legacy_migration requires allow_legacy_migration_write = true in [openrfid_api]"
            )
        return value

    @staticmethod
    def _timeout(params: dict) -> float:
        try:
            timeout = float(params.get("timeout", 10.0))
        except (TypeError, ValueError) as exc:
            raise ValueError("timeout must be a number") from exc
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
            raise ValueError("timeout must be greater than 0 and at most 30 seconds")
        return timeout
