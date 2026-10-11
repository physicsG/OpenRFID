"""Entry-point tests for lock-free cooperative process shutdown."""

from __future__ import annotations

import importlib
import signal
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

# The entry point imports target-only GPIO/SPI modules, but this test does not
# instantiate hardware. Minimal module shims keep the import contract honest.
sys.modules.setdefault("spidev", SimpleNamespace(SpiDev=object))
sys.modules.setdefault(
    "gpiod",
    SimpleNamespace(Chip=object, LINE_REQ_DIR_OUT=1),
)


def test_signal_handlers_only_request_runtime_shutdown(monkeypatch):
    main_module = importlib.import_module("main")
    installed = {}

    class _Runtime:
        def __init__(self):
            self.calls = 0

        def request_shutdown(self):
            self.calls += 1

    runtime = _Runtime()
    monkeypatch.setattr(
        main_module.signal,
        "signal",
        lambda signum, handler: installed.setdefault(signum, handler),
    )

    main_module._install_shutdown_signal_handlers(runtime)
    assert set(installed) == {signal.SIGTERM, signal.SIGINT}

    installed[signal.SIGTERM](signal.SIGTERM, None)
    installed[signal.SIGINT](signal.SIGINT, None)
    assert runtime.calls == 2
