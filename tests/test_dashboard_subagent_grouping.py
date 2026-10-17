"""Session view groups a subagent's calls under the turn that launched it.

Runs the trail-grouping JS from dashboard.html under node: subagent calls get
their own 'sub:<id>' group (not the main agent's Shell lane), the launch row
joins that group, work that lands after a later prompt stays with the launching
turn, and the finish notice becomes the subagent's outcome instead of a row.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_NODE = shutil.which("node")
_HTML = Path(__file__).resolve().parents[1] / "prismor" / "runtime" / "dashboard.html"

_DRIVER = r"""
const h = require('fs').readFileSync(process.argv[1], 'utf8');
const src = h.slice(h.indexOf('const LANE_LABEL'), h.indexOf('function treeRowEl'));
const groupTrail = new Function(src + '; return groupTrail;')();
const sub = (cmd) => ({type:'shell', lane:'shell', artifacts:{command:cmd, subagent_id:'abc', subagent_type:'fork'}});
const trail = [
  {type:'prompt', lane:'prompt', artifacts:{user_message:'audit everything'}},
  {type:'subagent_spawn', lane:'tools', artifacts:{description:'Audit A', response:'{"agentId": "abc"}'}},
  {type:'shell', lane:'shell', artifacts:{command:'ls'}},
  sub('git status'),
  {type:'prompt', lane:'prompt', artifacts:{user_message:'now something else'}},
  sub('pytest'),
  {type:'prompt', lane:'prompt', artifacts:{user_message:
    '<task-notification><task-id>abc</task-id><status>completed</status><summary>Agent "Audit A" finished</summary><result>All good.</result></task-notification>'}},
];
const turns = groupTrail(trail);
console.log(JSON.stringify(turns.map(t => ({
  lanes: Object.fromEntries([...t.lanes].map(([k, v]) => [k, v.length])),
  subs: t.subs || null,
}))));
"""


@pytest.mark.skipif(_NODE is None, reason="node not installed")
def test_subagent_calls_group_under_launching_turn():
    out = subprocess.run([_NODE, "-e", _DRIVER, str(_HTML)], capture_output=True, text=True, check=True)
    turns = json.loads(out.stdout)
    assert len(turns) == 2
    first, second = turns
    # Launch + both subagent calls (one arrived after the second prompt).
    assert first["lanes"]["sub:abc"] == 3
    assert first["lanes"]["shell"] == 1          # only the main agent's own call
    assert "sub:abc" not in second["lanes"]
    assert "task" not in first["lanes"] and "task" not in second["lanes"]
    sa = first["subs"]["abc"]
    assert sa["desc"] == "Audit A" and sa["type"] == "fork"
    assert sa["done"]["status"] == "completed" and sa["done"]["result"] == "All good."
