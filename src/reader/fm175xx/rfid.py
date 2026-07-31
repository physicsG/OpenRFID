from tag.mifare_classic_tag_processor import TagAuthentication
from tag.tag_types import TagType, tag_type_from_sak
from . import constants as Constants
from bus import SoftwareSPI, OutputPin
from reader.mifare_classic_reader import MifareClassicReader
from reader.mifare_ultralight_reader import (
    MifareUltralightReader,
    TIGERTAG_INIT_ID,
    TIGERTAG_MAKER_ID,
    TIGERTAG_PLUS_ID,
    TIGERTAG_OWNED_END_PAGE,
    TIGERTAG_OWNED_LENGTH,
    TIGERTAG_OWNED_START_PAGE,
)
from reader.scan_result import ScanResult
from config import get_required_configurable_entity_by_name, TYPE_SOFTWARE_SPI, TYPE_OUTPUT_PIN
from typing import Any, Callable, cast
import time


_NTAG21X_VERSION_MODELS = {
    # GET_VERSION storage-size byte: (model, dynamic-lock page).
    0x0F: ("NTAG213", 40),
    0x11: ("NTAG215", 130),
    0x13: ("NTAG216", 226),
}

# Reader command
class Fm175xxCmdMetaData:
    def __init__(self) -> None:
        self.cmd : int
        self.send_crc_en : int
        self.recv_crc_en : int
        self.bits_to_send : int
        self.bytes_to_send : int
        self.bits_to_recv : int
        self.bytes_to_recv : int
        self.bits_recved : int
        self.bytes_recved : int
        self.send_buff : list
        self.recv_buff : list
        self.coll_pos : int
        self.error : int
        self.timeout : int

# Return value
class Fm175xxReturnVal:
    def __init__(self) -> None:
        self.err_code : int = 0
        self.out_data : list[int] = []

class Fm175xx(MifareClassicReader, MifareUltralightReader):
    def __init__(self, config : dict):
        super().__init__(config)
        self.spi = cast(SoftwareSPI, get_required_configurable_entity_by_name(config["spi"], TYPE_SOFTWARE_SPI))
        self.reset_pin = cast(OutputPin, get_required_configurable_entity_by_name(config["reset_pin"], TYPE_OUTPUT_PIN))
        self.hard_reset()

    def hard_reset(self):
        self.reset_pin.set_low()
        time.sleep(0.100)
        self.reset_pin.set_high()
        time.sleep(0.200)

    def start_session(self):
        self.__reader_a_init()
        self.__set_carrier_wave(Constants.FM175XX_CW_ENABLE)

    def end_session(self):
        self.__reader_a_halt()
        self.__set_carrier_wave(Constants.FM175XX_CW_DISABLE)

    def scan(self) -> ScanResult | None:
        (ret, UID, ATQA, BCC, SAK) = self.__reader_a_activate()
        if (ret != Constants.FM175XX_OK):
            self.logger.error("Scan error: %d", ret)
            return None

        return ScanResult(tag_type_from_sak(bytes(SAK)), bytes(UID), bytes(ATQA), bytes(BCC), bytes(SAK))

    def read_mifare_classic(self, scan_result: ScanResult, keys: TagAuthentication) -> tuple[bytes|None, bool]:
        data = self.__reader_a_m1_read_all_data(list(scan_result.uid), Constants.FM175XX_M1_CARD_AUTH_MODE_A, keys)

        if data.err_code != Constants.FM175XX_OK:
            self.logger.error("Mifare Classic read error: %d", data.err_code)
            if data.err_code == Constants.FM175XX_CARD_AUTH_ERR:
                return None, False  # auth error is not retryable
            return None, True

        return bytes(data.out_data), False
    
    def read_mifare_ultralight(self, scan_result: ScanResult) -> bytes | None:
        data = self.__reader_a_ultralight_read_all_data()

        if data.err_code != Constants.FM175XX_OK:
            self.logger.error("Mifare Classic read error: %d", data.err_code)
            return None

        return bytes(data.out_data)

    def _write_ntag_pages_unchecked(self, start_page: int, data: bytes) -> int:
        """Legacy general NTAG writer retained for low-level diagnostics.

        This deliberately private method has no expected-UID, format or
        read-back safeguards. Product/API writes must use
        :meth:`write_tigertag_maker` or :meth:`clear_tigertag_maker`.
        """
        if not isinstance(data, (bytes, bytearray)):
            return Constants.FM175XX_PARAM_ERR
        if len(data) == 0 or len(data) % Constants.FM175XX_NTAG215_BYTES_PER_PAGE != 0:
            return Constants.FM175XX_PARAM_ERR

        total_pages = len(data) // Constants.FM175XX_NTAG215_BYTES_PER_PAGE
        end_page = start_page + total_pages - 1
        if start_page < Constants.FM175XX_NTAG215_USER_START_PAGE or end_page > Constants.FM175XX_NTAG215_USER_END_PAGE:
            self.logger.error(
                "NTAG write out of user-data range: pages %d..%d (allowed %d..%d)",
                start_page,
                end_page,
                Constants.FM175XX_NTAG215_USER_START_PAGE,
                Constants.FM175XX_NTAG215_USER_END_PAGE,
            )
            return Constants.FM175XX_PARAM_ERR

        ret, _UID, _ATQA, _BCC, _SAK = self.__reader_a_activate()
        if ret != Constants.FM175XX_OK:
            self.logger.error("NTAG write activate failed: %d", ret)
            return ret

        for i in range(total_pages):
            page_no = start_page + i
            chunk = list(data[i * 4:(i + 1) * 4])
            wret = self.__ntag_page_write(page_no, chunk)
            if wret != Constants.FM175XX_OK:
                self.logger.error("NTAG write failed at page %d: %d", page_no, wret)
                return wret

        return Constants.FM175XX_OK

    @staticmethod
    def _tag_operation_error(code: str, error: str, **details: Any) -> dict[str, Any]:
        return {"ok": False, "code": code, "error": error, **details}

    def _activate_expected_ultralight(
        self,
        expected_uid: bytes,
    ) -> tuple[bytes | None, dict[str, Any] | None]:
        ret, uid_raw, _atqa, _bcc, sak_raw = self.__reader_a_activate()
        if ret != Constants.FM175XX_OK:
            return None, self._tag_operation_error(
                "tag_not_present",
                "could not activate a tag",
                status=ret,
            )

        uid = bytes(uid_raw)
        tag_type = tag_type_from_sak(bytes(sak_raw))
        if tag_type != TagType.MifareUltralight:
            return None, self._tag_operation_error(
                "wrong_tag_type",
                "activated tag is not MIFARE Ultralight/NTAG hardware",
                actual_uid=uid.hex().upper(),
                actual_tag_type=tag_type.name,
            )
        if uid != expected_uid:
            return None, self._tag_operation_error(
                "uid_mismatch",
                "activated tag UID does not match expected_uid",
                expected_uid=expected_uid.hex().upper(),
                actual_uid=uid.hex().upper(),
            )
        return uid, None

    def _read_tigertag_owned_region(
        self,
    ) -> tuple[bytes | None, dict[str, Any] | None]:
        data = bytearray()
        for page in range(TIGERTAG_OWNED_START_PAGE, TIGERTAG_OWNED_END_PAGE + 1, 4):
            result = self.__reader_a_ultralight_page_read(page)
            if result.err_code != Constants.FM175XX_OK or len(result.out_data) != 16:
                code = "capacity_probe_failed" if page == 20 else "read_failed"
                message = (
                    "tag does not expose writable user memory through page 23"
                    if page == 20
                    else f"failed to read TigerTag-owned region at page {page}"
                )
                return None, self._tag_operation_error(
                    code,
                    message,
                    page=page,
                    status=result.err_code,
                )
            data.extend(result.out_data)
        return bytes(data[:TIGERTAG_OWNED_LENGTH]), None

    def _validate_existing_tigertag(
        self,
        current: bytes,
        allow_unrecognized: bool,
        allow_legacy_migration: bool,
        legacy_signature_prefix: bytes | None = None,
    ) -> tuple[str | None, dict[str, Any] | None]:
        header = int.from_bytes(current[:4], "big")
        if header == TIGERTAG_PLUS_ID:
            product_id = int.from_bytes(current[4:8], "big")
            # The retired feature encoder used the Plus format ID, reserved
            # product 0, and wrote a guaranteed zero signature prefix to pages
            # 24..27. All three conditions are required for migration; a
            # Plus-shaped tag without that exact read-only fingerprint stays
            # protected even when an override is supplied.
            if product_id == 0:
                if legacy_signature_prefix != bytes(16):
                    return None, self._tag_operation_error(
                        "protected_tag_format",
                        "TigerTag+ product 0 does not match the exact legacy OpenRFID v1 signature prefix",
                        existing_header=f"0x{header:08X}",
                        existing_product_id=product_id,
                    )
                if allow_legacy_migration:
                    return "legacy_openrfid_v1", None
                return None, self._tag_operation_error(
                    "legacy_upgrade_required",
                    "legacy unsigned TigerTag+ data requires the explicit legacy-migration override",
                    existing_header=f"0x{header:08X}",
                    existing_product_id=product_id,
                )
            return None, self._tag_operation_error(
                "protected_tag_format",
                "TigerTag+ is not writable by the Maker writer",
                existing_header=f"0x{header:08X}",
                existing_product_id=product_id,
            )
        if header == TIGERTAG_MAKER_ID:
            return "maker", None
        if header == TIGERTAG_INIT_ID:
            return "init", None
        if allow_unrecognized:
            return "unrecognized", None
        return None, self._tag_operation_error(
            "unrecognized_tag",
            "existing tag is neither TigerTag Maker nor TigerTag Init; explicit allow_unrecognized is required",
            existing_header=f"0x{header:08X}",
        )

    def _read_legacy_signature_prefix(
        self,
    ) -> tuple[bytes | None, dict[str, Any] | None]:
        result = self.__reader_a_ultralight_page_read(24)
        if result.err_code != Constants.FM175XX_OK or len(result.out_data) != 16:
            return None, self._tag_operation_error(
                "legacy_probe_failed",
                "could not verify pages 24..27 required for legacy OpenRFID v1 migration",
                page=24,
                status=result.err_code,
            )
        return bytes(result.out_data), None

    def _preflight_tigertag_writable(
        self,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """Fail closed on model, locks, CC access, or password protection.

        The writer owns pages 4..23. NTAG21x static locks cover pages 4..15;
        dynamic locks cover page 16 onward with model-specific granularity.
        Every check happens before page 4 is invalidated.
        """
        version_result = self.__ntag_get_version()
        version = bytes(version_result.out_data)
        if (
            version_result.err_code != Constants.FM175XX_OK
            or len(version) != 8
            or version[1:3] != b"\x04\x04"
            or version[6] not in _NTAG21X_VERSION_MODELS
        ):
            return None, self._tag_operation_error(
                "unsupported_tag_model",
                "safe writes require a recognized NTAG213, NTAG215, or NTAG216 GET_VERSION response",
                status=version_result.err_code,
                version_hex=version.hex().upper(),
            )

        model, dynamic_lock_page = _NTAG21X_VERSION_MODELS[version[6]]

        static_result = self.__reader_a_ultralight_page_read(2)
        if static_result.err_code != Constants.FM175XX_OK or len(static_result.out_data) != 16:
            return None, self._tag_operation_error(
                "lock_probe_failed",
                "could not read NTAG static lock bytes",
                page=2,
                status=static_result.err_code,
                tag_model=model,
            )
        static_window = bytes(static_result.out_data)
        static_lock_0 = static_window[2]
        static_lock_1 = static_window[3]
        locked_pages = [
            page
            for page in range(4, 8)
            if static_lock_0 & (1 << page)
        ]
        locked_pages.extend(
            page
            for page in range(8, 16)
            if static_lock_1 & (1 << (page - 8))
        )
        if locked_pages:
            return None, self._tag_operation_error(
                "tag_locked",
                "one or more TigerTag-owned pages are statically locked read-only",
                tag_model=model,
                lock_source="static",
                locked_pages=locked_pages,
            )

        # Page 3 is included in the READ(2) window. A non-zero Type 2 Tag CC
        # write-access nibble is not an unrestricted writable data area.
        cc_write_access = static_window[7] & 0x0F
        if cc_write_access != 0:
            return None, self._tag_operation_error(
                "tag_read_only",
                "the NFC Type 2 capability container does not allow unrestricted writes",
                tag_model=model,
                cc_write_access=cc_write_access,
            )

        dynamic_result = self.__reader_a_ultralight_page_read(dynamic_lock_page)
        if dynamic_result.err_code != Constants.FM175XX_OK or len(dynamic_result.out_data) != 16:
            return None, self._tag_operation_error(
                "lock_probe_failed",
                "could not read NTAG dynamic lock and configuration bytes",
                page=dynamic_lock_page,
                status=dynamic_result.err_code,
                tag_model=model,
            )
        dynamic_window = bytes(dynamic_result.out_data)
        dynamic_lock_0 = dynamic_window[0]
        if model == "NTAG213":
            dynamic_locked_pages = [
                page
                for page in range(16, 24)
                if dynamic_lock_0 & (1 << ((page - 16) // 2))
            ]
        else:
            dynamic_locked_pages = list(range(16, 24)) if dynamic_lock_0 & 0x01 else []
        if dynamic_locked_pages:
            return None, self._tag_operation_error(
                "tag_locked",
                "one or more TigerTag-owned pages are dynamically locked read-only",
                tag_model=model,
                lock_source="dynamic",
                locked_pages=dynamic_locked_pages,
            )

        # The READ(dynamic-lock-page) response also includes CFG0 on the next
        # page; AUTH0 is CFG0 byte 3. This writer intentionally has no password
        # input, so any protection beginning inside pages 4..23 is rejected.
        auth0 = dynamic_window[7]
        if auth0 <= TIGERTAG_OWNED_END_PAGE:
            return None, self._tag_operation_error(
                "tag_password_protected",
                "password protection begins inside the TigerTag-owned region",
                tag_model=model,
                auth0_page=auth0,
            )

        return {
            "tag_model": model,
            "version_hex": version.hex().upper(),
            "dynamic_lock_page": dynamic_lock_page,
        }, None

    def _replace_tigertag_owned_region(
        self,
        expected_uid: bytes,
        target: bytes,
        allow_unrecognized: bool,
        allow_legacy_migration: bool,
        action: str,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(expected_uid, (bytes, bytearray)) or len(expected_uid) not in (4, 7, 10):
            return self._tag_operation_error(
                "invalid_uid",
                "expected_uid must be a 4, 7, or 10 byte ISO14443 UID",
            )
        expected_uid = bytes(expected_uid)
        if not isinstance(target, (bytes, bytearray)) or len(target) != TIGERTAG_OWNED_LENGTH:
            return self._tag_operation_error(
                "invalid_payload_length",
                f"TigerTag-owned payload must be exactly {TIGERTAG_OWNED_LENGTH} bytes",
            )
        target = bytes(target)
        if action == "write" and int.from_bytes(target[:4], "big") != TIGERTAG_MAKER_ID:
            return self._tag_operation_error(
                "invalid_payload_header",
                f"payload header must be TigerTag Maker 0x{TIGERTAG_MAKER_ID:08X}",
            )

        uid, error = self._activate_expected_ultralight(expected_uid)
        if error is not None:
            return error

        # Reading all five 16-byte windows before the first write both records
        # the existing header and proves that page 23 is addressable.
        current, error = self._read_tigertag_owned_region()
        if error is not None:
            return error
        assert current is not None
        legacy_signature_prefix = None
        if (
            int.from_bytes(current[:4], "big") == TIGERTAG_PLUS_ID
            and int.from_bytes(current[4:8], "big") == 0
        ):
            legacy_signature_prefix, error = self._read_legacy_signature_prefix()
            if error is not None:
                return error
        existing_format, error = self._validate_existing_tigertag(
            current,
            allow_unrecognized,
            allow_legacy_migration,
            legacy_signature_prefix=legacy_signature_prefix,
        )
        if error is not None:
            return error

        preflight, error = self._preflight_tigertag_writable()
        if error is not None:
            return error
        assert preflight is not None

        # Recheck authoritative printer state after activation, UID matching,
        # format inspection, and the page-23 capacity probe, immediately
        # before the first mutating command. The Moonraker receive loop stays
        # responsive while this operation waits, so this sees print starts
        # that occurred after the API request was accepted.
        if safety_check is not None:
            try:
                blocked = safety_check()
            except Exception as exc:
                return self._tag_operation_error(
                    "safety_check_failed",
                    f"pre-write safety check failed: {exc}",
                    phase="pre_write",
                )
            if blocked is not None:
                if not isinstance(blocked, dict) or blocked.get("ok") is not False:
                    return self._tag_operation_error(
                        "invalid_safety_check_result",
                        "pre-write safety check returned an invalid result",
                        phase="pre_write",
                    )
                return {**blocked, "phase": "pre_write"}

        # Invalidate the format first. A power loss or later page error leaves
        # a deliberately unrecognized tag instead of a valid header over a
        # partially updated body.
        status = self.__ntag_page_write(TIGERTAG_OWNED_START_PAGE, [0, 0, 0, 0])
        if status != Constants.FM175XX_OK:
            return self._tag_operation_error(
                "header_invalidate_failed",
                "failed to invalidate the existing TigerTag header",
                page=TIGERTAG_OWNED_START_PAGE,
                status=status,
            )

        for page in range(TIGERTAG_OWNED_START_PAGE + 1, TIGERTAG_OWNED_END_PAGE + 1):
            offset = (page - TIGERTAG_OWNED_START_PAGE) * 4
            status = self.__ntag_page_write(page, list(target[offset:offset + 4]))
            if status != Constants.FM175XX_OK:
                return self._tag_operation_error(
                    "body_write_failed",
                    f"failed to write TigerTag body page {page}",
                    page=page,
                    status=status,
                    header_invalidated=True,
                )

        body_readback, error = self._read_tigertag_owned_region()
        if error is not None:
            return self._tag_operation_error(
                "body_verify_read_failed",
                error["error"],
                page=error.get("page"),
                status=error.get("status"),
                cause_code=error["code"],
                header_invalidated=True,
            )
        assert body_readback is not None
        if body_readback[4:] != target[4:]:
            return self._tag_operation_error(
                "body_verify_failed",
                "TigerTag body read-back did not match the requested data",
                header_invalidated=True,
            )

        # Publish the target header only after every body page verifies. Clear
        # operations intentionally publish a zero header here.
        status = self.__ntag_page_write(TIGERTAG_OWNED_START_PAGE, list(target[:4]))
        if status != Constants.FM175XX_OK:
            return self._tag_operation_error(
                "header_write_failed",
                "failed to write the final TigerTag header",
                page=TIGERTAG_OWNED_START_PAGE,
                status=status,
                header_invalidated=True,
            )

        full_readback, error = self._read_tigertag_owned_region()
        if error is not None:
            return self._tag_operation_error(
                "verify_read_failed",
                error["error"],
                page=error.get("page"),
                status=error.get("status"),
                cause_code=error["code"],
            )
        if full_readback != target:
            return self._tag_operation_error(
                "verify_failed",
                "full TigerTag read-back did not match the requested data",
            )

        return {
            "ok": True,
            "code": "written" if action == "write" else "cleared",
            "uid": uid.hex().upper() if uid is not None else expected_uid.hex().upper(),
            "previous_format": existing_format,
            "start_page": TIGERTAG_OWNED_START_PAGE,
            "end_page": TIGERTAG_OWNED_END_PAGE,
            "bytes_written": TIGERTAG_OWNED_LENGTH,
            "verified": True,
            "tag_model": preflight["tag_model"],
        }

    def write_tigertag_maker(
        self,
        expected_uid: bytes,
        data: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Safely write one 80-byte Maker record while a session is active."""
        return self._replace_tigertag_owned_region(
            expected_uid,
            data,
            allow_unrecognized,
            allow_legacy_migration,
            action="write",
            safety_check=safety_check,
        )

    def clear_tigertag_maker(
        self,
        expected_uid: bytes,
        allow_unrecognized: bool = False,
        allow_legacy_migration: bool = False,
        safety_check: Callable[[], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        """Safely clear exactly pages 4..23 while a session is active."""
        return self._replace_tigertag_owned_region(
            expected_uid,
            b"\x00" * TIGERTAG_OWNED_LENGTH,
            allow_unrecognized,
            allow_legacy_migration,
            action="clear",
            safety_check=safety_check,
        )

    # Reader-A: NTAG/Ultralight, write a page (4 bytes)
    def __ntag_page_write(self, page: int, data: list[int]) -> int:
        cmd = Fm175xxCmdMetaData()
        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_RESET
        cmd.send_buff = [0xA2, page & 0xFF, data[0] & 0xFF, data[1] & 0xFF, data[2] & 0xFF, data[3] & 0xFF]
        cmd.recv_buff = [0]
        cmd.bytes_to_send = 6
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 1
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE

        result = self.__command_exe(cmd)
        if result.err_code != Constants.FM175XX_OK:
            return result.err_code
        # NTAG ACK: 4 bits, low nibble == 0x0A
        if cmd.bits_recved != 4:
            return Constants.FM175XX_CARD_COMM_ERR
        if (cmd.recv_buff[0] & 0x0F) != 0x0A:
            return Constants.FM175XX_CARD_COMM_ERR
        return Constants.FM175XX_OK

    def __ntag_get_version(self) -> Fm175xxReturnVal:
        """Issue the NTAG21x GET_VERSION command (0x60)."""
        cmd = Fm175xxCmdMetaData()
        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = [0x60]
        cmd.recv_buff = [0] * 8
        cmd.bytes_to_send = 1
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 8
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        return self.__command_exe(cmd)

    # read register
    def __register_read(self, addr:int) -> int:
        addr = (addr << 1) | 0x80
        to_send = [addr, 0x00]
        reg_data = self.spi.transfer(to_send)
        return reg_data[1]
    
    # write register
    def __register_write(self, addr:int, reg_data:int) -> None:
        addr = (addr << 1) & 0x7E
        to_send = [addr, reg_data]
        self.spi.transfer(to_send)

    # modify register
    def __register_modify(self, addr:int, mask:int, is_set:int) -> None:
        reg_data = self.__register_read(addr)
        if (is_set):
            reg_data |= mask
        else:
            reg_data &= ~mask
        self.__register_write(addr, reg_data)

    # read FIFO
    def __fifo_read(self, len:int) -> list[int]:
        addr = [0x92] * len + [0x00]
        buff = self.spi.transfer(addr)
        return buff[1 : len + 1]

    # write FIFO
    def __fifo_write(self, len:int, buff:list) -> None:
        to_write = [0x12]
        to_write += buff[0:len]
        self.spi.transfer(to_write)

    # Enable/Disable CRC check generation during data transmission.
    def __set_send_crc(self, mode:int) -> None:
        if (mode):
            self.__register_modify(Constants.FM175XX_TX_MODE_REG, 0x80, Constants.FM175XX_SET)
        else:
            self.__register_modify(Constants.FM175XX_TX_MODE_REG, 0x80, Constants.FM175XX_RESET)

    # Enable/Disable CRC check generation during data reception.
    def __set_recv_crc(self, mode:int) -> None:
        if (mode):
            self.__register_modify(Constants.FM175XX_RX_MODE_REG, 0x80, Constants.FM175XX_SET)
        else:
            self.__register_modify(Constants.FM175XX_RX_MODE_REG, 0x80, Constants.FM175XX_RESET)

    # Set the timeout period for communication
    def __set_timeout(self, microseconds:int) -> None:
        prescaler = 0
        time_reload = 0

        if microseconds < 1 :
            microseconds = 1

        while( prescaler < 0xFFF ):
            time_reload = int((( microseconds * 13560 ) -1 ) / ( prescaler * 2 + 1))
            if (time_reload < 0xFFFF):
                break
            prescaler += 1

        time_reload &=  0xFFFF
        self.__register_write(Constants.FM175XX_T_MODE_REG, 0x80 | ((prescaler >> 8) & 0x0F) )
        self.__register_write(Constants.FM175XX_T_PRESCALER_REG, prescaler & 0xFF)
        self.__register_write(Constants.FM175XX_T_RELOAD_MSB_REG, time_reload >> 8 )
        self.__register_write(Constants.FM175XX_T_RELOAD_LSB_REG, time_reload & 0xFF )

    # set carrier wave
    def __set_carrier_wave(self, mode:int) -> None:
        if (Constants.FM175XX_CW1_ENABLE == mode):
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x01, Constants.FM175XX_SET)
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x02, Constants.FM175XX_RESET)
        elif (Constants.FM175XX_CW2_ENABLE == mode):
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x01, Constants.FM175XX_RESET)
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x02, Constants.FM175XX_SET)
        elif (Constants.FM175XX_CW_ENABLE == mode):
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x03, Constants.FM175XX_SET)
        else: # FM175XX_CW_DISABLE == mode
            self.__register_modify(Constants.FM175XX_TX_CONTROL_REG, 0x03, Constants.FM175XX_RESET)


    # Execute Command
    def __command_exe(self, cmd:Fm175xxCmdMetaData) -> Fm175xxReturnVal:
        reg_data = 0
        irq = 0
        result = Constants.FM175XX_ERR
        send_length = cmd.bytes_to_send
        receive_length = 0
        send_finish = 0
        cmd.bits_recved = 0
        cmd.bytes_recved = 0
        cmd.coll_pos = 0
        cmd.error = 0
        fifo_water_level  = 32
        last_time = time.time()

        self.__register_write(Constants.FM175XX_COMMAND_REG, Constants.FM175XX_CMD_IDLE)
        self.__register_write(Constants.FM175XX_FIFO_LEVEL_REG, 0x80)
        self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x7F)
        self.__register_write(Constants.FM175XX_DIV_IRQ_REG, 0x7F)
        self.__register_write(Constants.FM175XX_COM_I_EN_REG, 0x80)
        self.__register_write(Constants.FM175XX_DIV_I_EN_REG, 0x00)
        self.__register_write(Constants.FM175XX_WATER_LEVEL_REG, fifo_water_level)

        self.__set_send_crc(cmd.send_crc_en)
        self.__set_recv_crc(cmd.recv_crc_en)
        self.__set_timeout(cmd.timeout)

        # authentication
        if (cmd.cmd == Constants.FM175XX_CMD_MF_AUTHENT) :
            self.__fifo_write(send_length, cmd.send_buff)
            send_length = 0
            self.__register_write(Constants.FM175XX_COMMAND_REG, cmd.cmd)
            self.__register_write(Constants.FM175XX_BIT_FRAMING_REG, 0x80 | cmd.bits_to_send)

        if (cmd.cmd == Constants.FM175XX_CMD_TRANSCEIVE):
            self.__register_write(Constants.FM175XX_COMMAND_REG, cmd.cmd)
            self.__register_write(Constants.FM175XX_BIT_FRAMING_REG, (cmd.bits_to_recv << 4) | cmd.bits_to_send)

        last_time = time.time() * 1000
        while 1:
            # timeout
            new_time = time.time() * 1000
            if (new_time - last_time > 50 + cmd.timeout):
                result = Constants.FM175XX_CARD_TIMER_ERR
                break
            irq = self.__register_read(Constants.FM175XX_COM_IRQ_REG)

            # timeout
            if (irq & 0x01):
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x01)
                result = Constants.FM175XX_CARD_TIMER_ERR
                break

            # errors occurred
            if (irq & 0x02):
                reg_data = self.__register_read(Constants.FM175XX_ERROR_REG)
                cmd.error = reg_data

                if (cmd.error & 0x08):
                    reg_data = self.__register_read(Constants.FM175XX_COLL_REG)
                    cmd.coll_pos = reg_data & 0x1F
                    result = Constants.FM175XX_CARD_COLL_ERR
                    break

                result = Constants.FM175XX_CARD_COMM_ERR
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x02)
                break

            # low level alert
            if (irq & 0x04):
                # send data
                if (send_length > 0):
                    if (send_length > fifo_water_level):
                        self.__fifo_write(fifo_water_level, cmd.send_buff)
                        del cmd.send_buff[0:fifo_water_level]
                        send_length = send_length - fifo_water_level
                    else:
                        self.__fifo_write(send_length, cmd.send_buff)
                        send_length = 0
                    self.__register_modify(Constants.FM175XX_BIT_FRAMING_REG, 0x80, Constants.FM175XX_SET)
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x04)

            # high level alert
            if (irq & 0x08):
                # Waiting for data transmission to complete
                if (send_finish == 1):
                    cmd.recv_buff[cmd.bytes_recved:cmd.bytes_recved + fifo_water_level] = self.__fifo_read(fifo_water_level)
                    cmd.bytes_recved += fifo_water_level
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x08)

            # idle status
            if ((irq & 0x10) and (cmd.cmd == Constants.FM175XX_CMD_MF_AUTHENT)):
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x10)
                result = Constants.FM175XX_OK
                break

            # receice data
            if ((irq & 0x20) and (cmd.cmd == Constants.FM175XX_CMD_TRANSCEIVE)):
                reg_data = self.__register_read(Constants.FM175XX_CONTROL_REG)
                cmd.bits_recved = reg_data & 0x07
                reg_data = self.__register_read(Constants.FM175XX_FIFO_LEVEL_REG)
                receive_length = reg_data & 0x7F
                cmd.recv_buff[cmd.bytes_recved:cmd.bytes_recved+receive_length] = self.__fifo_read(receive_length)
                cmd.bytes_recved += receive_length
                if ((cmd.bytes_to_recv != cmd.bytes_recved) and (cmd.bytes_to_recv != 0)):
                    result = Constants.FM175XX_CARD_LENGTH_ERR
                    break
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x20)
                result = Constants.FM175XX_OK
                break

            # Completed data transmission
            if (irq & 0x40):
                self.__register_write(Constants.FM175XX_COM_IRQ_REG, 0x40)
                if (cmd.cmd == Constants.FM175XX_CMD_TRANSCEIVE):
                    send_finish = 1

        self.__register_modify(Constants.FM175XX_BIT_FRAMING_REG, 0x80, Constants.FM175XX_RESET)
        self.__register_write(Constants.FM175XX_COMMAND_REG, Constants.FM175XX_CMD_IDLE)

        ret = Fm175xxReturnVal()
        ret.err_code = result
        ret.out_data = cmd.recv_buff[:cmd.bytes_recved]

        if (len(ret.out_data) < cmd.bytes_recved):
            raise Exception("Fm175xx command exec error: recv data length less than expected")

        return ret

    # Reader-A: init
    def __reader_a_init(self) -> None:
        self.__register_write(Constants.FM175XX_TX_MODE_REG, 0x00)
        self.__register_write(Constants.FM175XX_RX_MODE_REG, 0x08)
        self.__register_modify(Constants.FM175XX_TX_AUTO_REG, 0x40, Constants.FM175XX_SET)
        self.__register_write(Constants.FM175XX_MODE_WIDTH_REG, 0x26)
        self.__register_write(Constants.FM175XX_CONTROL_REG, 0x10)
        self.__register_write(Constants.FM175XX_GSN_ON_REG, 0xF0)
        self.__register_write(Constants.FM175XX_CW_GSP_REG, 0x3F)
        self.__register_write(Constants.FM175XX_RF_CFG_REG, 0x60)
        self.__register_write(Constants.FM175XX_RX_THRESHOLD_REG, 0x84)
        self.__register_modify(Constants.FM175XX_STATUS_2_REG, 0x08, Constants.FM175XX_RESET)

    # Reader-A: wake up picc(s)
    def __reader_a_wakeup(self) -> tuple[int, list[int]]:
        ret = Constants.FM175XX_ERR
        outbuf = [0]
        inbuf = [0] * 2
        cmd = Fm175xxCmdMetaData()

        cmd.send_crc_en = Constants.FM175XX_RESET
        cmd.recv_crc_en = Constants.FM175XX_RESET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = Constants.FM175XX_RF_CMD_WUPA
        cmd.bytes_to_send = 1
        cmd.bits_to_send = 7
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 2
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret = result.err_code

        ATQA = [0, 0]

        if (result.err_code == Constants.FM175XX_OK):
            if (len(result.out_data) == 2):
                ATQA[0] = result.out_data[0]
                ATQA[1] = result.out_data[1]
            else:
                ret = Constants.FM175XX_CARD_COMM_ERR

        return (ret, ATQA)

    # Reader-A: anti-collision
    def __reader_a_anticoll(self, cascade_level:int) -> tuple[int, list[int], int]:
        ret = Constants.FM175XX_ERR
        outbuf = [0] * 2
        inbuf = [0] * 5
        cmd = Fm175xxCmdMetaData()

        if(cascade_level > 2):
            return (Constants.FM175XX_PARAM_ERR, [], 0)

        cmd.send_crc_en = Constants.FM175XX_RESET
        cmd.recv_crc_en = Constants.FM175XX_RESET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = Constants.FM175XX_RF_CMD_ANTICOL[cascade_level]
        cmd.send_buff[1] = 0x20
        cmd.bytes_to_send = 2
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 5
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret = result.err_code
        self.__register_modify(Constants.FM175XX_COLL_REG, 0x80, Constants.FM175XX_SET)

        UID_part = [0] * 4
        BCC_part = 0

        if (result.err_code == Constants.FM175XX_OK):
            if (len(result.out_data) == 5):
                if((result.out_data[0] ^ \
                    result.out_data[1] ^ \
                    result.out_data[2] ^ \
                    result.out_data[3] ^ \
                    result.out_data[4]) != 0):
                    ret = Constants.FM175XX_CARD_COMM_ERR
                else:
                    UID_part = result.out_data[0:4]
                    BCC_part = result.out_data[4]
            else:
                ret = Constants.FM175XX_CARD_COMM_ERR

        return (ret, UID_part, BCC_part)

    # Reader-A: select a picc
    def __reader_a_select(self, cascade_level : int, UID_part: list[int], BCC_part : int) -> tuple[int, int]:
        ret = Constants.FM175XX_ERR
        outbuf = [0] * 7
        inbuf = [0]
        cmd = Fm175xxCmdMetaData()

        if(cascade_level > 2 or len(UID_part) != 4):
            return (Constants.FM175XX_PARAM_ERR, 0)

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = Constants.FM175XX_RF_CMD_SELECT[cascade_level]
        cmd.send_buff[1] = 0x70
        cmd.send_buff[2] = UID_part[0]
        cmd.send_buff[3] = UID_part[1]
        cmd.send_buff[4] = UID_part[2]
        cmd.send_buff[5] = UID_part[3]
        cmd.send_buff[6] = BCC_part
        cmd.bytes_to_send = 7
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 1
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret = result.err_code

        SAK_part = 0

        if (result.err_code == Constants.FM175XX_OK):
            if (len(result.out_data) == 1):
                SAK_part = result.out_data[0]
            else:
                ret = Constants.FM175XX_CARD_COMM_ERR

        return (ret, SAK_part)

    # Reader-A: halt
    def __reader_a_halt(self) -> int:
        outbuf = [0] * 2
        inbuf = [0] * 2
        cmd = Fm175xxCmdMetaData()

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = Constants.FM175XX_RF_CMD_HALT[0]
        cmd.send_buff[1] = Constants.FM175XX_RF_CMD_HALT[1]
        cmd.bytes_to_send = 2
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 0
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)

        # If there is no response within 1ms, the 'halt' is successful
        if (result.err_code == Constants.FM175XX_CARD_TIMER_ERR):
            result.err_code = Constants.FM175XX_OK
        else:
            result.err_code = Constants.FM175XX_CARD_HALT_ERR

        return result.err_code

    # Reader-A: activate a picc
    def __reader_a_activate(self) -> tuple[int, list[int], list[int], list[int], list[int]]:
        ret = Constants.FM175XX_ERR
        cascade_level = 0

        (ret, ATQA) = self.__reader_a_wakeup()
        if (Constants.FM175XX_OK != ret):
            self.logger.error("wakeup err: %d", ret)
            return (Constants.FM175XX_CARD_WAKEUP_ERR, [], [], [], [])

        if ((ATQA[0] & 0xC0) == 0x00):
            cascade_level = 1
        elif ((ATQA[0] & 0xC0) == 0x40):
            cascade_level = 2
        elif ((ATQA[0] & 0xC0) == 0x80):
            cascade_level = 3
        else:
            pass  # RFU

        UID : list[int] = []
        BCC : list[int] = []
        SAK : list[int] = []

        for level in range(cascade_level):
            (ret, UID_part, BCC_part) = self.__reader_a_anticoll(level)
            if (Constants.FM175XX_OK != ret):
                self.logger.error("anticoll err: %d", ret)
                ret = Constants.FM175XX_CARD_COLL_ERR
                break

            if level < cascade_level - 1:
                UID += UID_part[1:]
            else:
                UID += UID_part
            BCC.append(BCC_part)

            (ret, SAK_part) = self.__reader_a_select(level, UID_part, BCC_part)
            if (Constants.FM175XX_OK != ret):
                self.logger.error("select err: %d", ret)
                ret = Constants.FM175XX_CARD_SELECT_ERR
                break

            SAK.append(SAK_part)

        if (Constants.FM175XX_OK != ret):
            return (ret, [], [], [], [])

        return (ret, UID, ATQA, BCC, SAK)

    # Reader-A: M1 authentication
    def __reader_a_mifare_auth(self, mode:int, sector:int, mifare_key:list, card_uid:list) -> int:
        ret = Constants.FM175XX_ERR
        reg_data = 0
        outbuf = [0] * 12
        inbuf = [0] * 1
        cmd = Fm175xxCmdMetaData()

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        if (Constants.FM175XX_M1_CARD_AUTH_MODE_A == mode):
            cmd.send_buff[0] = 0x60
        else:
            cmd.send_buff[0] = 0x61
        cmd.send_buff[1] = sector * 4
        cmd.send_buff[2] = mifare_key[0]
        cmd.send_buff[3] = mifare_key[1]
        cmd.send_buff[4] = mifare_key[2]
        cmd.send_buff[5] = mifare_key[3]
        cmd.send_buff[6] = mifare_key[4]
        cmd.send_buff[7] = mifare_key[5]
        cmd.send_buff[8] = card_uid[0]
        cmd.send_buff[9] = card_uid[1]
        cmd.send_buff[10] = card_uid[2]
        cmd.send_buff[11] = card_uid[3]
        cmd.bytes_to_send = 12
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 0
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_MF_AUTHENT
        result = self.__command_exe(cmd)
        ret = result.err_code
        if (Constants.FM175XX_OK == result.err_code):
            reg_data = self.__register_read(Constants.FM175XX_STATUS_2_REG)
            if (reg_data & 0x08):
                ret =  Constants.FM175XX_OK
            else:
                ret =  Constants.FM175XX_CARD_COMM_ERR

        return ret

    # Reader-A: M1, read a block
    def __reader_a_m1_block_read(self, block:int) -> Fm175xxReturnVal:
        outbuf = [0] * 2
        inbuf = [0] * 16
        cmd = Fm175xxCmdMetaData()
        ret = Fm175xxReturnVal()

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = 0x30
        cmd.send_buff[1] = block
        cmd.bytes_to_send = 2
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 16
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret.err_code = result.err_code

        if (Constants.FM175XX_OK == result.err_code):
            if (len(result.out_data) == 16):
                ret.out_data = result.out_data[0:16]
            else:
                ret.err_code = Constants.FM175XX_CARD_COMM_ERR

        return ret

    # Reader-A: M1, write a block
    def __reader_a_m1_block_write(self, block:int, buff:list) -> int:
        ret = 0
        outbuf = [0] * 16
        inbuf = [0] * 1
        cmd = Fm175xxCmdMetaData()

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_RESET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = 0xA0
        cmd.send_buff[1] = block
        cmd.bytes_to_send = 2
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 1
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret = result.err_code

        if ((result.err_code != Constants.FM175XX_OK) or (cmd.bits_recved != 4) or (cmd.recv_buff[0] & 0x0F != 0x0A)):
            if (result.err_code == Constants.FM175XX_OK):
                ret = Constants.FM175XX_CARD_COMM_ERR
        else:
            self.__set_timeout(10)
            cmd.send_buff[0:16] = buff[0:16]
            cmd.bytes_to_send = 16
            cmd.bytes_to_recv = 1
            cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
            result = self.__command_exe(cmd)
            ret = result.err_code

            if ((cmd.bits_recved != 4) or (cmd.recv_buff[0] & 0x0F != 0x0A)):
                ret = Constants.FM175XX_CARD_COMM_ERR

        return ret

    # Reader-A: M1, read all data
    def __reader_a_m1_read_all_data(self, uid:list, auth_mode:int, auth_key : TagAuthentication, retry_times = 3) -> Fm175xxReturnVal:
        ret = Fm175xxReturnVal()
        card_data_tmp = [0] * Constants.FM175XX_M1_CARD_EEPROM_SIZE
        area = 0

        # Traverse all sectors
        for sector_no in range(Constants.FM175XX_M1_CARD_SECTORS):
            # Authentication
            result = Constants.FM175XX_ERR
            #print(auth_key.hkdf_key_a[sector_no])
            for _ in range(retry_times):
                result = self.__reader_a_mifare_auth(auth_mode, sector_no, auth_key.hkdf_key_a[sector_no], uid)
                if (result == Constants.FM175XX_OK):
                    break
            if (Constants.FM175XX_OK != result):
                ret.err_code = Constants.FM175XX_CARD_AUTH_ERR
                self.logger.error( "------ M1 AUTH ERROR------\r\n" )
                return ret

            # Traverse all blocks
            for block_no in range(Constants.FM175XX_M1_CARD_BLOCKS_PER_SEC - 1):
                result = Fm175xxReturnVal()
                for _ in range(retry_times):
                    result = self.__reader_a_m1_block_read(sector_no * Constants.FM175XX_M1_CARD_BLOCKS_PER_SEC + block_no)
                    if (result.err_code == Constants.FM175XX_OK):
                        break
                if (result.err_code != Constants.FM175XX_OK):
                    ret.err_code = Constants.FM175XX_CARD_READ_ERR
                    return ret

                area = Constants.FM175XX_M1_CARD_BYTES_PER_BLK * (sector_no * Constants.FM175XX_M1_CARD_BLOCKS_PER_SEC + block_no)
                card_data_tmp[area : area + Constants.FM175XX_M1_CARD_BYTES_PER_BLK] = result.out_data[0 : Constants.FM175XX_M1_CARD_BYTES_PER_BLK]

            area = sector_no * Constants.FM175XX_M1_CARD_BYTES_PER_SEC + 3 * Constants.FM175XX_M1_CARD_BYTES_PER_BLK
            card_data_tmp[area : area + Constants.FM175XX_M1_CARD_BYTES_PER_BLK] = \
                    auth_key.hkdf_key_a[sector_no] + Constants.FM175XX_M1_CARD_ACCESS_CODE + auth_key.hkdf_key_b[sector_no]

        ret.err_code = Constants.FM175XX_OK
        ret.out_data = card_data_tmp
        return ret
    
    # Reader-A: NTAG/Ultralight, read a page (4 bytes)
    def __reader_a_ultralight_page_read(self, page:int) -> Fm175xxReturnVal:
        outbuf = [0] * 2
        inbuf = [0] * 16
        cmd = Fm175xxCmdMetaData()
        ret = Fm175xxReturnVal()

        cmd.send_crc_en = Constants.FM175XX_SET
        cmd.recv_crc_en = Constants.FM175XX_SET
        cmd.send_buff = outbuf
        cmd.recv_buff = inbuf
        cmd.send_buff[0] = 0x30
        cmd.send_buff[1] = page
        cmd.bytes_to_send = 2
        cmd.bits_to_send = 0
        cmd.bits_to_recv = 0
        cmd.bytes_to_recv = 16
        cmd.timeout = 10
        cmd.cmd = Constants.FM175XX_CMD_TRANSCEIVE
        result = self.__command_exe(cmd)
        ret.err_code = result.err_code

        if (Constants.FM175XX_OK == result.err_code):
            if (len(result.out_data) == 16):
                ret.out_data = result.out_data
            else:
                ret.err_code = Constants.FM175XX_CARD_COMM_ERR

        return ret

    # TODO: Maybe don't call it ultralight but the actual ISO specification
    # Reader-A: NTAG215, read all data
    def __reader_a_ultralight_read_all_data(self, retry_times = 3) -> Fm175xxReturnVal:
        ret = Fm175xxReturnVal()
        card_data_tmp = [0] * Constants.FM175XX_NTAG215_TOTAL_SIZE

        for page_no in range(0, Constants.FM175XX_NTAG215_TOTAL_PAGES, 4):
            result = Fm175xxReturnVal()
            for _ in range(retry_times):
                result = self.__reader_a_ultralight_page_read(page_no)
                if (result.err_code == Constants.FM175XX_OK):
                    break
            if (result.err_code != Constants.FM175XX_OK):
                if (page_no - 4) in Constants.FM175XX_ULTRALIGHT_VALID_END_PAGES:
                    card_data_tmp = card_data_tmp[0 : (page_no * Constants.FM175XX_NTAG215_BYTES_PER_PAGE)]
                    break

                ret.err_code = Constants.FM175XX_CARD_READ_ERR
                return ret

            area = page_no * Constants.FM175XX_NTAG215_BYTES_PER_PAGE
            bytes_to_copy = min(16, Constants.FM175XX_NTAG215_TOTAL_SIZE - area)
            if bytes_to_copy > 0:
                card_data_tmp[area : area + bytes_to_copy] = result.out_data[0 : bytes_to_copy]

        ret.err_code = Constants.FM175XX_OK
        ret.out_data = card_data_tmp
        return ret
