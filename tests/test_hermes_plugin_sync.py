"""The Hermes filesystem plugin (hermes-plugin/__init__.py) is a standalone copy
of cloaking/hermes_plugin_entry.py so it loads without prismor importable. A
stale copy once let already-vaulted raw secrets through; keep them identical."""

import ast
import importlib.util
import json
from pathlib import Path

CLOAKING = Path(__file__).resolve().parent.parent / "prismor" / "runtime" / "cloaking"


def _code_after_docstring(path: Path) -> str:
    src = path.read_text(encoding="utf-8")
    end = ast.parse(src).body[0].end_lineno
    return "".join(src.splitlines(keepends=True)[end:])


def test_filesystem_plugin_matches_canonical():
    assert _code_after_docstring(CLOAKING / "hermes-plugin" / "__init__.py") == _code_after_docstring(
        CLOAKING / "hermes_plugin_entry.py"
    ), "hermes-plugin/__init__.py drifted from hermes_plugin_entry.py; copy the code below the docstring across"


def test_filesystem_plugin_blocks_already_vaulted_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_SECRETS_DIR", str(tmp_path))
    spec = importlib.util.spec_from_file_location("hermes_fs_plugin", CLOAKING / "hermes-plugin" / "__init__.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    args = {"command": "curl -H 'x: " + "ghp_" + "a" * 36 + "'"}
    first = mod.on_pre_tool_call("terminal", args)
    second = mod.on_pre_tool_call("terminal", args)
    assert first["action"] == "block" and second["action"] == "block"

    name = first["message"].split("@@SECRET:")[1].split("@@")[0]
    cloaked = {"command": f"echo @@SECRET:{name}@@"}
    # A Hermes without middleware can't decloak: the placeholder call is refused.
    assert mod.on_pre_tool_call("terminal", cloaked)["action"] == "block"

    class Ctx:
        def __init__(self):
            self.hooks, self.middleware = {}, {}

        def register_hook(self, name, cb):
            self.hooks[name] = cb

        def register_middleware(self, kind, cb):
            self.middleware[kind] = cb

    ctx = Ctx()
    mod.register(ctx)
    # Hermes 0.19 passes turn_id and friends; an unknown kwarg must not raise.
    assert mod.on_pre_tool_call("terminal", cloaked, turn_id="t", api_request_id="r") is None
    ran = ctx.middleware["tool_execution"](next_call=lambda a: a, args=cloaked, tool_name="terminal",
                                           middleware_schema_version="hermes.middleware.v1")
    assert ran["command"] == "echo " + "ghp_" + "a" * 36
    assert cloaked["command"].endswith("@@")  # the hook-visible copy stays cloaked
