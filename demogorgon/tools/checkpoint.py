"""Checkpoint — recovered from legacy checkpoint.py.

Atomic state persistence with crash recovery and signal handlers.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Checkpoint:
    def __init__(self, checkpoint_dir: str = ".demogorgon/checkpoints"):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._dirty = False
        self._data: dict[str, Any] = {}
        self._filename = "research_checkpoint.json"
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        original_sigint = signal.getsignal(signal.SIGINT)
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _emergency_save(signum, frame):
            if self._dirty:
                try:
                    self.save_sync()
                except Exception:
                    pass
            if signum == signal.SIGINT:
                original_sigint(signum, frame)
            else:
                original_sigterm(signum, frame)

        signal.signal(signal.SIGINT, _emergency_save)
        signal.signal(signal.SIGTERM, _emergency_save)

    def update(self, key: str, value: Any) -> None:
        self._data[key] = value
        self._dirty = True

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def save_sync(self) -> str:
        filepath = self.checkpoint_dir / self._filename
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=self.checkpoint_dir, suffix=".tmp"
        )
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(self._data, f, indent=2, default=str)
            os.replace(tmp_path, filepath)
            self._dirty = False
            return str(filepath)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    async def save(self) -> str:
        return await asyncio.to_thread(self.save_sync)

    def load_sync(self) -> bool:
        filepath = self.checkpoint_dir / self._filename
        if not filepath.exists():
            return False
        try:
            with open(filepath) as f:
                self._data = json.load(f)
            self._dirty = False
            return True
        except (json.JSONDecodeError, IOError):
            return False

    async def load(self) -> bool:
        return await asyncio.to_thread(self.load_sync)

    def recovery_plan(self) -> dict[str, Any]:
        return {
            "has_checkpoint": (self.checkpoint_dir / self._filename).exists(),
            "dirty": self._dirty,
            "keys": list(self._data.keys()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def clear(self) -> None:
        self._data = {}
        self._dirty = False
        filepath = self.checkpoint_dir / self._filename
        if filepath.exists():
            filepath.unlink()
