from controllers.controller import Controller
import socket
from abc import abstractmethod
import json
from typing import Any
import os
import threading
import time

class MoonrakerController(Controller):
    def __init__(self, config: dict):
        super().__init__(config)
        self.moonraker_socket_path = str(config["moonraker_socket_path"])
        self.socket : socket.socket|None = None
        self.buffer = b""
        # Agent event pumps and guarded write handlers may respond from worker
        # threads. Keep JSON frames contiguous on the shared Unix socket.
        self._send_lock = threading.Lock()
        self._connection_generation = 0
        self._connection_connected = False

    def current_connection_generation(self) -> int | None:
        """Return the active socket generation, or ``None`` while offline."""
        with self._send_lock:
            if not self._connection_connected or self.socket is None:
                return None
            return self._connection_generation

    def is_connection_current(self, generation: int | None) -> bool:
        """Whether *generation* still identifies the connected socket."""
        if generation is None:
            return False
        with self._send_lock:
            return (
                self._connection_connected
                and self.socket is not None
                and self._connection_generation == generation
            )
    
    def __loop_inner(self):
        if not os.path.exists(self.moonraker_socket_path):
            self.logger.warning(f"Moonraker socket not found at {self.moonraker_socket_path}")
            return

        connected_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connected = False
        try:
            connected_socket.connect(self.moonraker_socket_path)
            with self._send_lock:
                old_socket = self.socket
                self.socket = connected_socket
                self.buffer = b""
                self._connection_generation += 1
                self._connection_connected = True
                connected = True
            if old_socket is not None and old_socket is not connected_socket:
                old_socket.close()

            time.sleep(0.1)
            self.on_connect()

            while True:
                data = connected_socket.recv(4096)
                if not data:
                    raise Exception("Moonraker socket connection closed")

                self.buffer += data

                while b'\x03' in self.buffer:
                    message_data, self.buffer = self.buffer.split(b'\x03', 1)
                    try:
                        message = json.loads(message_data.decode("utf-8").strip())
                        self.on_message(message)
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to decode JSON message: {e}")
                        continue
        finally:
            with self._send_lock:
                if self.socket is connected_socket:
                    self.socket = None
                    self._connection_connected = False
                    self.buffer = b""
            try:
                connected_socket.close()
            finally:
                if connected:
                    self.on_disconnect()

    def loop(self):
        while True:
            try:
                self.__loop_inner()
            except Exception as e:
                self.logger.error(f"Error in MoonrakerController loop: {e}")

            self.logger.info("Retrying connection in 5 seconds...")
            time.sleep(5)

    def send_message(
        self,
        message: Any,
        expected_generation: int | None = None,
    ) -> bool:
        """Send one frame, optionally only on the request's original socket.

        Returning ``False`` for a stale generation lets worker threads discard
        replies after a reconnect instead of attaching an old JSON-RPC id to a
        new Moonraker connection.
        """
        message_str = json.dumps(message)
        payload = message_str.encode("utf-8") + b'\x03'
        with self._send_lock:
            if expected_generation is not None and (
                not self._connection_connected
                or self._connection_generation != expected_generation
            ):
                return False
            if self.socket is None:
                raise RuntimeError("Moonraker socket is not connected")
            self.socket.sendall(payload)
            return True

    def on_connect(self):
        """Called when the socket connection is established."""
        pass

    def on_disconnect(self):
        """Called immediately after the active socket is disconnected."""
        pass

    @abstractmethod
    def on_message(self, message: Any):
        """Handle a message received from the Moonraker socket."""
        raise NotImplementedError("Subclasses must implement this method")
