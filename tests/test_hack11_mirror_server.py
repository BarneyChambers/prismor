"""already_screened skips only the mirror's own server name."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from prismor.runtime import mirror


class TestMirrorServer(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._env = mock.patch.dict(os.environ, {"PRISMOR_HOME": self._tmp})
        self._env.start()
        self.ws = Path(self._tmp) / "ws"
        self.ws.mkdir()
        mirror.mark_active(self.ws, ["Bash"])

    def tearDown(self):
        mirror.clear_active(self.ws)
        self._env.stop()

    def test_other_server_is_not_skipped(self):
        self.assertFalse(mirror.already_screened("mcp__other__Bash", self.ws))
        self.assertTrue(mirror.already_screened("mcp__prismor-tools__Bash", self.ws))
        self.assertFalse(mirror.already_screened("Bash", self.ws))
        self.assertFalse(mirror.already_screened("mcp__other__Read", self.ws))
