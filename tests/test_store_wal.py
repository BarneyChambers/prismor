"""A reader holding the store must not cost hook writes.

With SQLite's default rollback journal, one read transaction held for over 5 s
(a dashboard query on a multi-GB store) made every concurrent hook's snapshot
fail with "database is locked": three parallel Codex subagent calls each waited
~10 s and none reached the store (laptop, 2026-10-17). The store runs in WAL
mode, where readers and writers don't block each other.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _dispatch(env, ws, i):
    payload = {"session_id": "s-wal", "cwd": str(ws), "hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": f"echo sub-{i}"}, "tool_use_id": f"x{i}",
               "agent_id": f"sub-{i}", "agent_type": "default"}
    return subprocess.run([sys.executable, "-m", "prismor.runtime.cli", "hook-dispatch", "--agent", "codex",
                           "--mode", "enforce", "--workspace", str(ws)],
                          input=json.dumps(payload), text=True, capture_output=True, env=env, timeout=120)


def test_hook_writes_go_through_while_a_reader_holds_the_store(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith("PRISMOR_")}
    env.update(HOME=str(tmp_path), PRISMOR_HOME=str(tmp_path / ".prismor"), PYTHONPATH=str(ROOT))
    _dispatch(env, ws, 0)                                    # creates the store
    db = tmp_path / ".prismor" / "prismor.db"
    assert sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0] == "wal"

    held, release = threading.Event(), threading.Event()

    def reader():
        c = sqlite3.connect(db, timeout=30)
        c.execute("BEGIN")
        c.execute("select count(*) from events").fetchone()  # holds a read snapshot
        held.set()
        release.wait(8)                                      # longer than sqlite's 5 s busy wait
        c.rollback()
        c.close()

    t = threading.Thread(target=reader)
    t.start()
    held.wait(5)
    start = time.time()
    results = []
    calls = [threading.Thread(target=lambda i=i: results.append(_dispatch(env, ws, i))) for i in (1, 2, 3)]
    for c in calls:
        c.start()
    for c in calls:
        c.join()
    took = time.time() - start
    release.set()
    t.join()

    assert all("database is locked" not in r.stderr for r in results), [r.stderr[-300:] for r in results]
    stored = sqlite3.connect(db).execute(
        "select count(distinct json_extract(raw_json,'$.metadata.subagent_id')) from events "
        "where session_id='s-wal' and json_extract(raw_json,'$.metadata.subagent_id') like 'sub-%' "
        "and json_extract(raw_json,'$.metadata.subagent_id') != 'sub-0'").fetchone()[0]
    assert stored == 3
    assert took < 5, f"hooks waited on the reader ({took:.1f}s)"


def test_merging_a_wal_store_keeps_rows_still_in_its_wal_file(tmp_path):
    from prismor.runtime.store import _merge_sqlite_db_once
    src, dst = tmp_path / "src.db", tmp_path / "dst.db"
    w = sqlite3.connect(src)
    w.execute("PRAGMA journal_mode=WAL")
    w.execute("PRAGMA wal_autocheckpoint=0")          # keep the row in src.db-wal
    w.execute("create table sessions (id integer primary key, session_id text)")
    w.execute("insert into sessions (session_id) values ('only-in-wal')")
    w.commit()                                         # left open: no checkpoint on close
    assert (tmp_path / "src.db-wal").stat().st_size > 0
    _merge_sqlite_db_once(src, dst)
    w.close()
    assert sqlite3.connect(dst).execute("select session_id from sessions").fetchall() == [("only-in-wal",)]
