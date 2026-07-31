"""Moonraker agent controller exposing OpenRFID over JSON-RPC.

Registers a Moonraker *agent* named ``openrfid`` that:

* exposes the remote methods ``openrfid/list_channels``, ``openrfid/scan_slot``,
  ``openrfid/write_tag``, ``openrfid/clear_tag`` and ``openrfid/tigertag_encode``,
* broadcasts ``notify_agent_event`` notifications (event name
  ``openrfid/scan``) for every scan event picked up from a configured
  :class:`exporters.openrfid_agent_event.OpenrfidAgentEventExporter`.

Write operations (``write_tag`` / ``clear_tag``) are gated behind the
``enable_write`` config flag (default ``false``) so installations that don't
want write access stay safe by default.
"""

from __future__ import annotations

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
_MSG_ID_REGISTER_METHOD_BASE = 0x6F1A0010

REMOTE_METHOD_LIST_CHANNELS = "openrfid/list_channels"
REMOTE_METHOD_SCAN_SLOT = "openrfid/scan_slot"
REMOTE_METHOD_WRITE_TAG = "openrfid/write_tag"
REMOTE_METHOD_CLEAR_TAG = "openrfid/clear_tag"
REMOTE_METHOD_TIGERTAG_ENCODE = "openrfid/tigertag_encode"


class OpenrfidApiController(MoonrakerController):
    """Moonraker agent that surfaces OpenRFID to Mainsail/Fluidd-style UIs."""

    def __init__(self, config: dict):
        super().__init__(config)
        self.runtime: Runtime
        self.enable_write = str(config.get("enable_write", "false")).lower() == "true"
        self.agent_event_exporter_name = config.get("agent_event_exporter", None)

        self._exporter: OpenrfidAgentEventExporter | None = None
        self._broadcast_thread: threading.Thread | None = None
        self._stop_broadcast = threading.Event()
        self._send_lock = threading.Lock()

        self._handlers: dict[str, Callable[[dict], Any]] = {
            REMOTE_METHOD_LIST_CHANNELS: self._handle_list_channels,
            REMOTE_METHOD_SCAN_SLOT: self._handle_scan_slot,
            REMOTE_METHOD_WRITE_TAG: self._handle_write_tag,
            REMOTE_METHOD_CLEAR_TAG: self._handle_clear_tag,
            REMOTE_METHOD_TIGERTAG_ENCODE: self._handle_tigertag_encode,
        }

    def send_message(self, message: Any):
        with self._send_lock:
            super().send_message(message)

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
        self._send_register_agent()
        time.sleep(0.05)
        for offset, method in enumerate(self._handlers):
            self._send_register_remote_method(method, _MSG_ID_REGISTER_METHOD_BASE + offset)
            time.sleep(0.02)

        # Start (or restart) the broadcast pump.
        self._stop_broadcast.set()
        if self._broadcast_thread and self._broadcast_thread.is_alive():
            self._broadcast_thread.join(timeout=1.0)
        self._stop_broadcast = threading.Event()
        self._broadcast_thread = threading.Thread(
            target=self._broadcast_loop, name="openrfid-agent-broadcast", daemon=True
        )
        self._broadcast_thread.start()

    def on_message(self, message: dict):
        method = message.get("method")
        if not method or method not in self._handlers:
            return

        msg_id = message.get("id")
        params = message.get("params") or {}
        if isinstance(params, list):
            params = params[0] if params and isinstance(params[0], dict) else {}

        try:
            result = self._handlers[method](params)
            response: dict[str, Any] = {"jsonrpc": "2.0", "result": result}
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Handler for %s failed", method)
            response = {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(exc)}}

        if msg_id is not None:
            response["id"] = msg_id
            try:
                self.send_message(response)
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
                "version": "0.1.0",
                "type": "agent",
                "url": "https://github.com/macdylan/SnapmakerU1-Extended-Firmware",
            },
            "id": _MSG_ID_REGISTER_AGENT,
        })

    def _send_register_remote_method(self, method_name: str, msg_id: int):
        self.send_message({
            "jsonrpc": "2.0",
            "method": "connection.register_remote_method",
            "params": {"method_name": method_name},
            "id": msg_id,
        })

    def _broadcast_loop(self):
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
                self.send_message({
                    "jsonrpc": "2.0",
                    "method": "connection.send_event",
                    "params": {
                        "event": "openrfid/scan",
                        "data": event,
                    },
                })
            except Exception:
                self.logger.exception("Failed to broadcast agent event; reconnect imminent")
                return

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------
    def _handle_list_channels(self, _params: dict) -> dict:
        channels = []
        for i, reader in enumerate(self.runtime.rfid_readers):
            channels.append({
                "slot": getattr(reader, "slot", i),
                "name": reader.name,
                "last_scan": self.runtime.last_scans.get(getattr(reader, "slot", i)),
            })
        return {"channels": channels, "write_enabled": self.enable_write}

    def _handle_scan_slot(self, params: dict) -> dict:
        slot = self._require_slot(params)
        if slot < 0 or slot >= len(self.runtime.rfid_readers):
            return {"ok": False, "error": f"invalid slot {slot}"}
        self.runtime.start_reading_tag(slot)
        return {"ok": True, "slot": slot}

    def _handle_write_tag(self, params: dict) -> dict:
        if not self.enable_write:
            return {"ok": False, "error": "writes disabled (set enable_write = true in [openrfid_api])"}
        slot = self._require_slot(params)
        data_hex = params.get("data_hex") or params.get("data")
        if not isinstance(data_hex, str):
            return {"ok": False, "error": "data_hex (string) required"}
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            return {"ok": False, "error": f"invalid hex: {exc}"}
        start_page = int(params.get("start_page", 4))
        timeout = float(params.get("timeout", 10.0))
        return self.runtime.submit_write(slot, data, start_page=start_page, timeout=timeout)

    def _handle_clear_tag(self, params: dict) -> dict:
        if not self.enable_write:
            return {"ok": False, "error": "writes disabled (set enable_write = true in [openrfid_api])"}
        slot = self._require_slot(params)
        pages = int(params.get("pages", tigertag_encoder.PAYLOAD_LENGTH_BYTES // 4))
        start_page = int(params.get("start_page", tigertag_encoder.USER_DATA_START_PAGE))
        data = b"\x00" * (pages * 4)
        return self.runtime.submit_write(slot, data, start_page=start_page)

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
            "data_hex": payload.hex(),
            "start_page": tigertag_encoder.USER_DATA_START_PAGE,
            "bytes": len(payload),
        }

    @staticmethod
    def _require_slot(params: dict) -> int:
        slot = params.get("slot")
        if slot is None:
            raise ValueError("slot is required")
        return int(slot)
