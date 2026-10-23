"""Migration must not follow secret symlinks or replace a home finding."""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from prismor.runtime import store


class TestMigrationCopy(unittest.TestCase):
    def test_symlink_is_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "sessions"
            src.mkdir()
            secret = root / "id_rsa"
            secret.write_text("KEY-MATERIAL", encoding="utf-8")
            (src / "leak").symlink_to(secret)
            dst = root / "out"
            store._copy_tree_contents_once(src, dst)
            self.assertFalse((dst / "leak").exists())

    def test_existing_finding_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home.db"
            work = root / "work.db"
            for path, severity, mode, action in (
                (home, "CRITICAL", "enforce", "block"),
                (work, "LOW", "observe", "warn"),
            ):
                con = sqlite3.connect(path)
                con.execute(
                    "CREATE TABLE findings (finding_id TEXT PRIMARY KEY, severity TEXT, "
                    "mode TEXT, action TEXT)"
                )
                con.execute(
                    "INSERT INTO findings VALUES ('f1', ?, ?, ?)",
                    (severity, mode, action),
                )
                if path == work:
                    con.execute(
                        "INSERT INTO findings VALUES ('f2', 'HIGH', 'enforce', 'block')"
                    )
                con.commit()
                con.close()
            store._merge_sqlite_db_once(work, home)
            row = sqlite3.connect(home).execute(
                "SELECT severity, mode, action FROM findings WHERE finding_id = 'f1'"
            ).fetchone()
            self.assertEqual(row, ("CRITICAL", "enforce", "block"))
            added = sqlite3.connect(home).execute(
                "SELECT finding_id FROM findings WHERE finding_id = 'f2'"
            ).fetchone()
            self.assertEqual(added, ("f2",))
