"""The model must learn WHY a tool call was refused (field test, 2026-10-15).

AutoGen Core handed the model a bare ``Error: `` and BeeAI raised a generic
``EmitterError`` the agent loop never catches, so both blocks reached the model
(or crashed the run) with no reason. Skipped when the framework isn't installed.
"""
import asyncio
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_DANGEROUS = "rm -rf / --no-preserve-root"


def _adapter_path(pkg: str) -> None:
    src = str(_ROOT / "adapters" / pkg)
    if src not in sys.path:
        sys.path.insert(0, src)


def test_autogen_core_block_reason_reaches_the_model(tmp_path):
    pytest.importorskip("autogen_core")
    _adapter_path("autogen-core")
    from autogen_core import FunctionCall
    from autogen_core.tool_agent import ToolException
    from prismor_autogen_core import PrismorInterventionHandler

    handler = PrismorInterventionHandler(workspace=tmp_path, mode="enforce")
    call = FunctionCall(id="c1", name="run_shell", arguments='{"command": "%s"}' % _DANGEROUS)
    with pytest.raises(ToolException) as exc:
        asyncio.run(handler.on_send(call, message_context=None, recipient="tool"))
    # tool_agent_caller_loop builds f"Error: {exc}" -- that is what the model reads.
    assert "Prismor blocked" in f"Error: {exc.value}"


def test_beeai_block_is_a_tool_error_with_the_reason(tmp_path):
    pytest.importorskip("beeai_framework")
    _adapter_path("beeai")
    from pydantic import BaseModel
    from beeai_framework.emitter import Emitter
    from beeai_framework.tools import StringToolOutput, Tool, ToolError
    from prismor_beeai import guard_tool

    ran = []

    class In(BaseModel):
        command: str

    class Shell(Tool[In, None, StringToolOutput]):
        name = "shell"
        description = "run a command"
        input_schema = In

        def _create_emitter(self):
            return Emitter.root().child(namespace=["tool", "shell"], creator=self)

        async def _run(self, input, options, context):
            ran.append(input.command)
            return StringToolOutput("ok")

    tool = guard_tool(Shell(), workspace=tmp_path, mode="enforce")

    async def call(command):
        return await tool.run({"command": command})

    assert asyncio.run(call("echo hi")).get_text_content() == "ok"
    # ToolError is what BeeAI agents catch and hand to the model.
    with pytest.raises(ToolError, match="Prismor blocked"):
        asyncio.run(call(_DANGEROUS))
    assert ran == ["echo hi"]


def test_agno_block_is_the_tool_result_not_an_error(tmp_path):
    """Raising made Agno log an ERROR + traceback for every expected block."""
    _adapter_path("agno")
    from prismor_agno import make_tool_hook

    ran = []
    hook = make_tool_hook(workspace=tmp_path, mode="enforce")
    out = hook("run_shell", lambda **kw: ran.append(kw) or "ran", {"command": _DANGEROUS})
    assert out.startswith("⛔ Prismor blocked") and ran == []
    assert hook("run_shell", lambda **kw: "ran", {"command": "echo hi"}) == "ran"


def test_a_reason_is_not_printed_twice():
    """Scoped/IAM findings repeat the title as evidence (seen via Google ADK)."""
    from prismor.runtime.runtime import _block_reason
    why = "delete_file is not allowed for user 'alice'"
    out = _block_reason({"severity": "HIGH", "title": f"[iam:user:alice] {why}", "evidence": why})
    assert out.count(why) == 1
    assert "evidence line" in _block_reason({"title": "t", "evidence": "evidence line"})
