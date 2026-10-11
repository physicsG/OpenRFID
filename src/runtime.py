from config import TYPE_CONTROLLER, TYPE_CONFIGURATION, get_required_configurable_entity_by_name, TYPE_EXPORTER, TYPE_TAG_PROCESSOR, TYPE_RFID_READER, get_entities_by_type
from config.configuration import default_configuration, Configuration
from controllers.controller import Controller
from tag.tag_types import TagType
from tag.tag_processor import TagProcessor
from tag.mifare_classic_tag_processor import MifareClassicTagProcessor
from tag.mifare_ultralight_tag_processor import MifareUltralightTagProcessor
from reader.mifare_classic_reader import MifareClassicReader
from reader.mifare_ultralight_reader import (
    MifareUltralightReader,
    TIGERTAG_MAKER_ID,
    TIGERTAG_OWNED_LENGTH,
)
from reader.rfid_reader import RfidReader
from exporters.exporter import Exporter, ExporterEvent
from reader.scan_result import ScanResult
from filament import GenericFilament
from typing import cast, Any, Callable
from collections import OrderedDict
import threading
import time
import logging
import math
import re
import uuid


class _PendingWrite:
    """One immutable tag operation awaiting drain by :meth:`Runtime.loop`."""

    __slots__ = (
        "operation_id",
        "slot",
        "action",
        "expected_uid",
        "data",
        "allow_unrecognized",
        "allow_legacy_migration",
        "safety_check",
        "event",
        "result",
        "state",
        "created_at",
        "started_at",
    )

    def __init__(
        self,
        operation_id: str,
        slot: int,
        action: str,
        expected_uid: bytes,
        data: bytes | None,
        allow_unrecognized: bool,
        allow_legacy_migration: bool,
        safety_check: Callable[[], dict[str, Any] | None] | None,
    ):
        self.operation_id = operation_id
        self.slot = slot
        self.action = action
        self.expected_uid = expected_uid
        self.data = data
        self.allow_unrecognized = allow_unrecognized
        self.allow_legacy_migration = allow_legacy_migration
        self.safety_check = safety_check
        self.event = threading.Event()
        self.result: dict[str, Any] | None = None
        self.state = "queued"
        self.created_at = time.time()
        self.started_at: float | None = None


class Runtime:
    TIGERTAG_OPERATION_HISTORY_LIMIT = 64

    def __init__(self):
        configs = cast(list[Configuration], get_entities_by_type(TYPE_CONFIGURATION))

        if len(configs) == 0:
            configs = [default_configuration()]
        elif len(configs) >= 2:
            logging.warning(f"Multiple configurations found, using the first one: {[config.name for config in configs]}")

        self.config = configs[0]

        self.rfid_readers : list[RfidReader] = [x for x in cast(list[RfidReader], get_entities_by_type(TYPE_RFID_READER)) if x.enabled]
        self._rebuild_reader_slot_mapping()
        self.tag_processors : list[TagProcessor] = [x for x in cast(list[TagProcessor], get_entities_by_type(TYPE_TAG_PROCESSOR)) if x.enabled]
        self.exporters : list[Exporter] = [x for x in cast(list[Exporter], get_entities_by_type(TYPE_EXPORTER)) if x.enabled]
        self.controllers : list[Controller] = [x for x in cast(list[Controller], get_entities_by_type(TYPE_CONTROLLER)) if x.enabled]

        logging.debug(f"Tag processors: {','.join([processor.name for processor in self.tag_processors])}")
        logging.debug(f"Exporters: {','.join([exporter.name for exporter in self.exporters])}")

        for controller in self.controllers:
            controller.runtime = self # type: ignore

        self.mifare_classic_processors = [processor for processor in self.tag_processors if isinstance(processor, MifareClassicTagProcessor)]
        self.mifare_ultralight_processors = [processor for processor in self.tag_processors if isinstance(processor, MifareUltralightTagProcessor)]

        self.read_retries_left = [0] * len(self.rfid_readers)

        # Pending safe TigerTag operations keyed by logical reader slot. They
        # are drained inside :meth:`loop` so all RFID bus access stays on the read
        # thread. An entry remains present while running, which makes the
        # per-slot busy check and timeout cleanup race-safe.
        self._pending_writes: dict[int, _PendingWrite] = {}
        self._pending_write_lock = threading.Lock()
        self._tigertag_operation_history: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._tigertag_operation_history_limit = self.TIGERTAG_OPERATION_HISTORY_LIMIT
        # Signal handlers only set this event. The RFID loop performs queue
        # cancellation so a signal cannot deadlock on the operation lock or
        # interrupt a transaction after its first page mutation.
        self._shutdown_requested = threading.Event()

        # Most recent scan event per slot. Populated whenever exporters are
        # notified so the Moonraker agent API can answer ``list_channels``
        # without re-scanning.
        self.last_scans: dict[int, dict] = {}

    def _rebuild_reader_slot_mapping(self) -> None:
        """Build the logical-slot lookup shared by every runtime operation."""
        reader_index_by_slot: dict[int, int] = {}
        reader_slot_by_index: list[int] = []
        for reader_index, reader in enumerate(self.rfid_readers):
            slot = getattr(reader, "slot", None)
            if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0:
                raise ValueError(
                    f"RFID reader {getattr(reader, 'name', reader_index)!r} has invalid slot {slot!r}"
                )
            if slot in reader_index_by_slot:
                first_index = reader_index_by_slot[slot]
                raise ValueError(
                    f"duplicate RFID reader slot {slot} at indexes {first_index} and {reader_index}"
                )
            reader_index_by_slot[slot] = reader_index
            reader_slot_by_index.append(slot)

        self._reader_index_by_slot = reader_index_by_slot
        self._reader_slot_by_index = tuple(reader_slot_by_index)

    def _resolve_reader_slot(self, slot: Any) -> tuple[int, RfidReader] | None:
        if not isinstance(slot, int) or isinstance(slot, bool):
            return None
        reader_index = self._reader_index_by_slot.get(slot)
        if reader_index is None:
            return None
        return reader_index, self.rfid_readers[reader_index]

    def _notify_exporters(self, scan: ScanResult|None, filament: GenericFilament|None, reader: RfidReader, event: ExporterEvent):
        slot = getattr(reader, "slot", None)
        if slot is not None:
            self.last_scans[int(slot)] = {
                "event": event.value,
                "ts": time.time(),
                "slot": int(slot),
                "reader": getattr(reader, "name", None),
                "uid": scan.uid.hex().upper() if scan is not None else None,
                "tag_type": scan.tag_type.name if scan is not None else None,
                "filament": filament.to_dict() if filament is not None else None,
            }

        for exporter in self.exporters:
            if exporter.has_event(event):
                exporter.export_data(scan, filament, reader)

    # ------------------------------------------------------------------
    # Pending safe TigerTag operations (used by the OpenRFID agent API).
    # ------------------------------------------------------------------
    @staticmethod
    def _write_error(code: str, error: str, **details: Any) -> dict[str, Any]:
        return {"ok": False, "code": code, "error": error, **details}

    def request_shutdown(self) -> None:
        """Request cooperative shutdown without blocking the signal handler."""
        self._shutdown_requested.set()

    def is_shutting_down(self) -> bool:
        return self._shutdown_requested.is_set()

    def _cancel_queued_tigertag_operations(self) -> int:
        """Cancel queued operations while allowing a running write to finish."""
        cancelled: list[_PendingWrite] = []
        with self._pending_write_lock:
            for slot, pending in list(self._pending_writes.items()):
                if pending.state != "queued":
                    continue
                self._pending_writes.pop(slot, None)
                result = self._write_error(
                    "service_stopping",
                    "OpenRFID is stopping; queued tag operation was cancelled",
                    operation_id=pending.operation_id,
                    slot=pending.slot,
                )
                pending.result = result
                pending.state = "cancelled"
                self._remember_tigertag_operation_locked(
                    pending,
                    result,
                    "cancelled",
                )
                cancelled.append(pending)

        for pending in cancelled:
            pending.event.set()
        return len(cancelled)

    def _remember_tigertag_operation_locked(
        self,
        pending: _PendingWrite,
        result: dict[str, Any],
        terminal_state: str,
    ) -> None:
        """Store one terminal operation while the operation lock is held."""
        status = {
            "ok": True,
            "operation_id": pending.operation_id,
            "operation_state": terminal_state,
            "completed": True,
            "action": pending.action,
            "slot": pending.slot,
            "expected_uid": pending.expected_uid.hex().upper(),
            "created_at": pending.created_at,
            "started_at": pending.started_at,
            "completed_at": time.time(),
            "result": dict(result),
        }
        self._tigertag_operation_history[pending.operation_id] = status
        self._tigertag_operation_history.move_to_end(pending.operation_id)
        while len(self._tigertag_operation_history) > self._tigertag_operation_history_limit:
            self._tigertag_operation_history.popitem(last=False)

    def get_tigertag_operation_status(self, operation_id: str) -> dict[str, Any]:
        """Return active state or a retained terminal result for an operation."""
        if not isinstance(operation_id, str) or not operation_id.strip():
            return self._write_error(
                "invalid_operation_id",
                "operation_id must be a non-empty string",
            )

        with self._pending_write_lock:
            for pending in self._pending_writes.values():
                if pending.operation_id == operation_id:
                    return {
                        "ok": True,
                        "operation_id": pending.operation_id,
                        "operation_state": pending.state,
                        "completed": False,
                        "action": pending.action,
                        "slot": pending.slot,
                        "expected_uid": pending.expected_uid.hex().upper(),
                        "created_at": pending.created_at,
                        "started_at": pending.started_at,
                    }

            retained = self._tigertag_operation_history.get(operation_id)
            if retained is not None:
                response = dict(retained)
                response["result"] = dict(retained["result"])
                return response

        return self._write_error(
            "operation_not_found",
            f"unknown or expired TigerTag operation {operation_id}",
            operation_id=operation_id,
        )

    @staticmethod
    def _normalize_expected_uid(value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray)):
            uid = bytes(value)
        elif isinstance(value, str):
            compact = re.sub(r"[\s:_-]", "", value.strip())
            if compact.lower().startswith("0x"):
                compact = compact[2:]
            if not compact or len(compact) % 2:
                raise ValueError("expected_uid must contain an even number of hex digits")
            try:
                uid = bytes.fromhex(compact)
            except ValueError as exc:
                raise ValueError("expected_uid must be hexadecimal") from exc
        else:
            raise ValueError("expected_uid is required as hex text or bytes")

        if len(uid) not in (4, 7, 10):
            raise ValueError("expected_uid must be a 4, 7, or 10 byte ISO14443 UID")
        return uid

    def get_tigertag_write_capabilities(self, slot: int) -> dict[str, Any]:
        """Describe the narrow write contract supported by one reader slot."""
        resolved = self._resolve_reader_slot(slot)
        if resolved is None:
            return {
                "supported": False,
                "code": "invalid_slot",
                "slot": slot,
            }
        _, reader = resolved
        write_impl = getattr(type(reader), "write_tigertag_maker", None)
        clear_impl = getattr(type(reader), "clear_tigertag_maker", None)
        supported = (
            callable(getattr(reader, "write_tigertag_maker", None))
            and callable(getattr(reader, "clear_tigertag_maker", None))
            and write_impl is not MifareUltralightReader.write_tigertag_maker
            and clear_impl is not MifareUltralightReader.clear_tigertag_maker
        )
        with self._pending_write_lock:
            active = self._pending_writes.get(slot)
            busy = active is not None
            active_operation_id = active.operation_id if active is not None else None
            active_state = active.state if active is not None else None
        return {
            "supported": supported,
            "format": "tigertag",
            "variant": "maker",
            "expected_uid_required": True,
            "payload_bytes": TIGERTAG_OWNED_LENGTH,
            "start_page": 4,
            "end_page": 23,
            "clear_supported": supported,
            "allow_unrecognized_supported": True,
            "allow_legacy_migration_supported": True,
            "busy": busy,
            "active_operation_id": active_operation_id,
            "active_state": active_state,
            "service_stopping": self._shutdown_requested.is_set(),
        }

    def submit_tigertag_write(
        self,
        slot: int,
        expected_uid: str | bytes,
        data: bytes,
        timeout: float = 10.0,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Write one fixed TigerTag Maker record to pages 4..23.

        ``expected_uid`` is mandatory. It binds the operation to the tag the
        caller reviewed; the low-level reader activates the tag again and
        requires an exact match before touching user memory.
        """
        if not isinstance(data, (bytes, bytearray)):
            return self._write_error("invalid_payload", "data must be bytes")
        payload = bytes(data)
        if len(payload) != TIGERTAG_OWNED_LENGTH:
            return self._write_error(
                "invalid_payload_length",
                f"TigerTag Maker payload must be exactly {TIGERTAG_OWNED_LENGTH} bytes",
                expected_bytes=TIGERTAG_OWNED_LENGTH,
                actual_bytes=len(payload),
            )
        if int.from_bytes(payload[:4], "big") != TIGERTAG_MAKER_ID:
            return self._write_error(
                "invalid_payload_header",
                f"payload header must be TigerTag Maker 0x{TIGERTAG_MAKER_ID:08X}",
            )
        return self._submit_tigertag_operation(
            slot=slot,
            action="write",
            expected_uid=expected_uid,
            data=payload,
            timeout=timeout,
            allow_unrecognized=allow_unrecognized,
            allow_legacy_migration=allow_legacy_migration,
            safety_check=safety_check,
        )

    def submit_tigertag_clear(
        self,
        slot: int,
        expected_uid: str | bytes,
        timeout: float = 10.0,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Clear exactly pages 4..23 after the same guarded tag checks."""
        return self._submit_tigertag_operation(
            slot=slot,
            action="clear",
            expected_uid=expected_uid,
            data=None,
            timeout=timeout,
            allow_unrecognized=allow_unrecognized,
            allow_legacy_migration=allow_legacy_migration,
            safety_check=safety_check,
        )

    def _submit_tigertag_operation(
        self,
        slot: int,
        action: str,
        expected_uid: str | bytes,
        data: bytes | None,
        timeout: float,
        allow_unrecognized: bool,
        allow_legacy_migration: bool,
        safety_check: Callable[[], dict[str, Any] | None] | None,
    ) -> dict[str, Any]:
        if self._resolve_reader_slot(slot) is None:
            return self._write_error("invalid_slot", f"invalid slot {slot}")
        if not isinstance(allow_unrecognized, bool):
            return self._write_error(
                "invalid_allow_unrecognized",
                "allow_unrecognized must be a boolean",
            )
        if not isinstance(allow_legacy_migration, bool):
            return self._write_error(
                "invalid_allow_legacy_migration",
                "allow_legacy_migration must be a boolean",
            )
        if safety_check is not None and not callable(safety_check):
            return self._write_error(
                "invalid_safety_check",
                "safety_check must be callable",
            )
        try:
            uid = self._normalize_expected_uid(expected_uid)
        except ValueError as exc:
            return self._write_error("invalid_uid", str(exc))
        try:
            wait_seconds = float(timeout)
        except (TypeError, ValueError):
            return self._write_error("invalid_timeout", "timeout must be a positive number")
        if not math.isfinite(wait_seconds) or wait_seconds <= 0:
            return self._write_error("invalid_timeout", "timeout must be a positive finite number")

        pending = _PendingWrite(
            operation_id=uuid.uuid4().hex,
            slot=slot,
            action=action,
            expected_uid=uid,
            data=data,
            allow_unrecognized=allow_unrecognized,
            allow_legacy_migration=allow_legacy_migration,
            safety_check=safety_check,
        )
        with self._pending_write_lock:
            if self._shutdown_requested.is_set():
                return self._write_error(
                    "service_stopping",
                    "OpenRFID is stopping; refusing a new tag operation",
                    slot=slot,
                )
            active = self._pending_writes.get(slot)
            if active is not None:
                return self._write_error(
                    "slot_busy",
                    f"slot {slot} already has a tag operation in progress",
                    slot=slot,
                    active_operation_id=active.operation_id,
                    active_state=active.state,
                )
            self._pending_writes[slot] = pending

        # Use the existing scan-trigger path so auto/manual modes both wake.
        try:
            self.start_reading_tag(slot)
        except Exception as exc:
            failure = self._write_error(
                "queue_wakeup_failed",
                f"could not wake the RFID loop: {exc}",
                operation_id=pending.operation_id,
                slot=slot,
            )
            cancelled = False
            with self._pending_write_lock:
                if self._pending_writes.get(slot) is pending and pending.state == "queued":
                    self._pending_writes.pop(slot, None)
                    pending.state = "cancelled"
                    pending.result = failure
                    self._remember_tigertag_operation_locked(pending, failure, "cancelled")
                    cancelled = True
            if cancelled:
                pending.event.set()
                return failure
            logging.warning(
                "RFID loop wake failed after operation %s started; waiting for its result",
                pending.operation_id,
            )

        if pending.event.wait(timeout=wait_seconds):
            return pending.result or self._write_error(
                "missing_result",
                "tag operation completed without a result",
                operation_id=pending.operation_id,
            )

        # Only cancel this exact operation while it is still queued. Once the
        # read loop marks it running, leave it registered and busy: removing a
        # running request would allow another operation to touch the same bus.
        cancelled_result: dict[str, Any] | None = None
        with self._pending_write_lock:
            current = self._pending_writes.get(slot)
            if pending.result is not None:
                return pending.result
            if current is pending and pending.state == "queued":
                self._pending_writes.pop(slot, None)
                pending.state = "cancelled"
                cancelled_result = self._write_error(
                    "timeout",
                    "timeout waiting for tag operation; queued operation was cancelled",
                    operation_id=pending.operation_id,
                    slot=slot,
                )
                pending.result = cancelled_result
                self._remember_tigertag_operation_locked(
                    pending,
                    cancelled_result,
                    "cancelled",
                )
            elif current is pending:
                return self._write_error(
                    "timeout_in_progress",
                    "timeout expired after tag operation started; slot remains busy until it finishes",
                    operation_id=pending.operation_id,
                    slot=slot,
                    operation_state=pending.state,
                )

        if cancelled_result is not None:
            pending.event.set()
            return cancelled_result

        return self._write_error(
            "timeout",
            "timeout waiting for tag operation",
            operation_id=pending.operation_id,
            slot=slot,
        )

    def _drain_pending_write(self, slot: int) -> bool:
        """Run one queued safe tag operation on the RFID loop thread."""
        resolved = self._resolve_reader_slot(slot)
        if resolved is None:
            return False
        reader_index, reader = resolved

        with self._pending_write_lock:
            pending = self._pending_writes.get(slot)
            cancel_for_shutdown = (
                pending is not None
                and pending.state == "queued"
                and self._shutdown_requested.is_set()
            )
            should_run = (
                pending is not None
                and pending.state == "queued"
                and not cancel_for_shutdown
            )
            if cancel_for_shutdown:
                self._pending_writes.pop(slot, None)
                result = self._write_error(
                    "service_stopping",
                    "OpenRFID is stopping; queued tag operation was cancelled",
                    operation_id=pending.operation_id,
                    slot=pending.slot,
                )
                pending.result = result
                pending.state = "cancelled"
                self._remember_tigertag_operation_locked(
                    pending,
                    result,
                    "cancelled",
                )
            elif pending is not None and pending.state == "queued":
                pending.state = "running"
                pending.started_at = time.time()
        if pending is None:
            return False
        if cancel_for_shutdown:
            pending.event.set()
            return True
        if not should_run:
            return True

        # Consume the wake-up used to run the operation. A successful result
        # schedules a separate read below so callers can verify fresh content.
        self.read_retries_left[reader_index] = 0
        method_name = "write_tigertag_maker" if pending.action == "write" else "clear_tigertag_maker"
        operation = getattr(reader, method_name, None)
        result: dict[str, Any]

        try:
            if not callable(operation):
                result = self._write_error(
                    "reader_not_supported",
                    f"reader does not support safe TigerTag {pending.action} operations",
                )
            else:
                session_started = False
                try:
                    reader.start_session()
                    session_started = True
                    def operation_safety_check() -> dict[str, Any] | None:
                        if self._shutdown_requested.is_set():
                            return self._write_error(
                                "service_stopping",
                                "OpenRFID is stopping; refusing to begin tag mutation",
                                phase="pre_write",
                            )
                        if pending.safety_check is not None:
                            return pending.safety_check()
                        return None

                    if pending.action == "write":
                        kwargs = {
                            "allow_unrecognized": pending.allow_unrecognized,
                            "allow_legacy_migration": pending.allow_legacy_migration,
                        }
                        kwargs["safety_check"] = operation_safety_check
                        result = operation(pending.expected_uid, pending.data, **kwargs)
                    else:
                        kwargs = {
                            "allow_unrecognized": pending.allow_unrecognized,
                            "allow_legacy_migration": pending.allow_legacy_migration,
                        }
                        kwargs["safety_check"] = operation_safety_check
                        result = operation(pending.expected_uid, **kwargs)
                    if not isinstance(result, dict) or "ok" not in result or "code" not in result:
                        result = self._write_error(
                            "invalid_reader_result",
                            "reader returned an invalid safe-write result",
                        )
                finally:
                    if session_started:
                        reader.end_session()
        except Exception as exc:
            logging.exception("Safe TigerTag %s failed on slot %d", pending.action, slot)
            result = self._write_error("reader_exception", str(exc))
        finally:
            result.setdefault("operation_id", pending.operation_id)
            result.setdefault("action", pending.action)
            result.setdefault("slot", slot)
            result.setdefault("expected_uid", pending.expected_uid.hex().upper())
            if result.get("ok") is True:
                reader.last_read_uid = None
                self.last_scans.pop(slot, None)
                if not self._shutdown_requested.is_set():
                    try:
                        self.start_reading_tag(slot)
                    except Exception:
                        logging.exception(
                            "Could not schedule verification scan after TigerTag %s on slot %d",
                            pending.action,
                            slot,
                        )
            with self._pending_write_lock:
                if self._pending_writes.get(slot) is pending:
                    self._pending_writes.pop(slot, None)
                pending.result = result
                pending.state = "completed"
                self._remember_tigertag_operation_locked(pending, result, "completed")
            pending.event.set()
        return True

    def start_reading_tag(self, slot: int):
        resolved = self._resolve_reader_slot(slot)
        if resolved is None:
            logging.error(f"Invalid slot number: {slot}")
            return

        reader_index, _ = resolved
        self.read_retries_left[reader_index] = self.config.read_retries
        logging.info(f"Received request to read tag on slot {slot} with {self.config.read_retries} retries")

    def loop(self):
        try:
            self._loop_until_shutdown()
        finally:
            self._cancel_queued_tigertag_operations()

    def _loop_until_shutdown(self):
        while not self._shutdown_requested.is_set():
            for i, reader in enumerate(self.rfid_readers):
                if self._shutdown_requested.is_set():
                    break
                slot = self._reader_slot_by_index[i]
                # Pending writes take priority over reads — they have an
                # impatient caller blocked on them. Skip the read this tick.
                if self._drain_pending_write(slot):
                    continue

                if not self.config.auto_read_mode and self.read_retries_left[i] <= 0:
                    continue

                logging.debug(f"Processing reader {reader.name}, retries left: {self.read_retries_left[i]}")
                try:
                    scan_result, filament, retry = self.process_reader_single(reader)
                except Exception as e:
                    logging.exception(f"Error processing reader {reader.name}: {e}")
                    scan_result, filament, retry = None, None, False # Assume exceptions are not transient

                if retry and self.read_retries_left[i] <= 1:
                    retry = False # Don't allow retry if this is the last retry left

                if retry:
                    self.read_retries_left[i] -= 1
                    logging.info(f"No tag detected on reader {reader.name}, will retry, retries left: {self.read_retries_left[i]}")
                    continue
                
                if filament:
                    logging.info(f"Successfully read tag with UID {scan_result.uid.hex().upper()} on reader {reader.name}")
                    self._notify_exporters(scan_result, filament, reader, ExporterEvent.TAG_READ)
                    self.read_retries_left[i] = 0
                elif scan_result:
                    logging.info(f"Detected tag with UID {scan_result.uid.hex().upper()} on reader {reader.name} but failed to read data")
                    self._notify_exporters(scan_result, None, reader, ExporterEvent.TAG_PARSE_ERROR)
                    self.read_retries_left[i] = 0
                elif self.config.auto_read_mode: # Auto-mode
                    # TODO: if tag was previously detected, it should at least once notify exporters about tag not present
                    logging.info(f"No tag detected on reader {reader.name}, but auto read mode is enabled, will retry")
                else: # Fatal non-retrable error
                    logging.info(f"No tag detected on reader {reader.name}")
                    self._notify_exporters(None, None, reader, ExporterEvent.TAG_NOT_PRESENT)
                    self.read_retries_left[i] = 0

            self._shutdown_requested.wait(self.config.read_interval_seconds)

    def process_reader_single(self, reader: RfidReader) -> tuple[ScanResult|None, GenericFilament|None, bool]:
        reader.start_session()
        scan_result = reader.scan()
        reader.end_session()
        if scan_result is None:
            logging.debug("No tag detected")
            return None, None, True
        
        uid = scan_result.uid.hex()
        
        if self.config.auto_read_mode and reader.is_same_tag(uid):
            logging.debug("Same tag detected as last read, skipping processing")
            return None, None, False
        
        logging.info(scan_result.pretty_text())

        filament = None
        retry = False
        if scan_result.tag_type == TagType.MifareClassic1k and isinstance(reader, MifareClassicReader):
            filament, retry = self.process_mifare_classic(reader, scan_result)
        elif scan_result.tag_type == TagType.MifareUltralight and isinstance(reader, MifareUltralightReader):
            filament, retry = self.process_mifare_ultralight(reader, scan_result)

        if filament:
            logging.info(filament.pretty_text())
            reader.set_last_read_uid(uid)
        else:
            logging.warning(f"Failed to read data from tag.")

        return (scan_result, filament, retry)

    def process_mifare_classic(self, reader: MifareClassicReader, scan_result: ScanResult) -> tuple[GenericFilament | None, bool]:
        any_retryable = False

        for processor in self.mifare_classic_processors:
            reader.start_session()

            if reader.scan() == None:
                logging.warning("Tag lost before reading")
                reader.end_session()
                return None, True

            logging.debug(f"Attempting to read with processor: {processor.name}")
            auth = processor.authenticate_tag(scan_result)

            if auth is None:
                logging.warning("Authentication failed with processor, skipping processor")
                reader.end_session()
                continue

            card_data, retryable = reader.read_mifare_classic(scan_result, auth)
            reader.end_session()

            if card_data is not None:
                logging.debug(f"Read MIFARE Classic card data: {card_data.hex().upper()}")
                return processor.process_tag(scan_result, card_data), False

            logging.warning("Failed to read MIFARE Classic card data")
            if retryable:
                any_retryable = True

        return None, any_retryable
    
    def process_mifare_ultralight(self, reader: MifareUltralightReader, scan_result: ScanResult) -> tuple[GenericFilament | None, bool]:
        reader.start_session()

        if reader.scan() == None:
            logging.warning("Tag lost before reading")
            reader.end_session()
            return None, True

        card_data = reader.read_mifare_ultralight(scan_result)
        reader.end_session()

        if card_data is not None:
            logging.debug(f"Read MIFARE Ultralight card data: {card_data.hex().upper()}")

            for processor in self.mifare_ultralight_processors:
                logging.debug(f"Attempting to read with processor: {processor.name}")
                filament = processor.process_tag(scan_result, card_data)
                if filament is not None:
                    return filament, False

            return None, False
        else:
            logging.warning("Failed to read MIFARE Ultralight card data")
            return None, True
