"""Exporter that buffers scan events for the OpenRFID Moonraker agent API.

This exporter is intentionally decoupled from any controller: it simply pushes
serialised event dictionaries onto a thread-safe queue. The matching
:class:`controllers.openrfid_api.OpenrfidApiController` (when configured)
drains the queue and broadcasts the events as Moonraker ``notify_agent_event``
JSON-RPC notifications.

If no controller is wired up, events are still queued (bounded) so the
exporter never raises and stays cheap.
"""

from __future__ import annotations

import queue
import time
from typing import Any

from exporters.exporter import Exporter, ExporterEvent
from filament.generic import GenericFilament
from reader.rfid_reader import RfidReader
from reader.scan_result import ScanResult


_DEFAULT_MAX_QUEUED = 64


class OpenrfidAgentEventExporter(Exporter):
    """Push every configured scan event onto a bounded in-memory queue."""

    def __init__(self, config: dict):
        # Default to all three events when none specified — the agent API
        # consumer normally wants the full stream.
        if "events" not in config and "event" not in config:
            config = {**config, "events": "tag_read,tag_parse_error,tag_not_present"}

        super().__init__(config)

        self.max_queued = int(config.get("max_queued", _DEFAULT_MAX_QUEUED))
        self._queue: "queue.Queue[dict]" = queue.Queue(maxsize=self.max_queued)

    def export_data(self, scan: ScanResult | None, filament: GenericFilament | None, reader: RfidReader) -> None:
        # Determine which event this call corresponds to. Exporter.has_event
        # has already filtered by the configured event set, so we infer here.
        if filament is not None:
            event = ExporterEvent.TAG_READ
        elif scan is not None:
            event = ExporterEvent.TAG_PARSE_ERROR
        else:
            event = ExporterEvent.TAG_NOT_PRESENT

        payload: dict[str, Any] = {
            "event": event.value,
            "ts": time.time(),
            "slot": getattr(reader, "slot", None),
            "reader": getattr(reader, "name", None),
            "uid": scan.uid.hex().upper() if scan is not None else None,
            "tag_type": scan.tag_type.name if scan is not None else None,
            "filament": filament.to_dict() if filament is not None else None,
        }

        # Drop oldest if full so the producer never blocks.
        if self._queue.full():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass

        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            # Last-ditch: silently drop. We never block the read loop.
            self.logger.debug("Agent event queue full, dropping event")

    def pop_event(self, timeout: float | None = 0.5) -> dict | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self) -> list[dict]:
        events: list[dict] = []
        while True:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                return events
