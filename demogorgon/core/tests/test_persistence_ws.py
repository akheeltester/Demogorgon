"""Tests for persistence and WebSocket events."""

import pytest
import os
import tempfile
import asyncio
from demogorgon.tools.checkpoint import Checkpoint

@pytest.mark.asyncio
async def test_persistence_and_recovery():
    """Verify that state can be persisted and recovered seamlessly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a checkpoint manager
        cp = Checkpoint(checkpoint_dir=tmpdir)

        # Save initial state
        state_to_save = {"iteration": 5, "strategy": "recon", "findings": []}
        cp._data = state_to_save  # Internal data structure for test
        await cp.save()

        # Verify file exists
        files = os.listdir(tmpdir)
        assert len(files) == 1
        assert files[0].endswith(".json")

        # Recover state
        cp2 = Checkpoint(checkpoint_dir=tmpdir)
        cp2.load_sync()
        assert cp2._data is not None
        assert cp2._data["iteration"] == 5
        assert cp2._data["strategy"] == "recon"
