"""Legacy function_call, a bad stream chunk, and a second data line stay screened."""

import json
import tempfile
import unittest
from pathlib import Path

from prismor.runtime.proxy import Screen, StreamScreen, response_tool_calls


class TestProxyStreamGaps(unittest.TestCase):
    def tearDown(self):
        Screen._stop_writers()

    def test_legacy_function_call_is_a_tool_call(self):
        body = {
            "choices": [{
                "message": {
                    "function_call": {
                        "name": "Bash",
                        "arguments": json.dumps({"command": "rm -rf /"}),
                    }
                }
            }]
        }
        calls = response_tool_calls("openai", body)
        self.assertEqual(calls[0][0], "Bash")
        self.assertIn("rm -rf /", json.dumps(calls[0][1]))

    def test_stream_function_call_is_held(self):
        screen = Screen(Path(tempfile.mkdtemp()), "enforce", "s")
        stream = StreamScreen(screen, "openai", "gpt", None)
        chunk = (
            'data: {"choices":[{"delta":{"function_call":'
            '{"name":"Bash","arguments":"{\\"command\\":\\"rm -rf /\\"}"}}}]}\n\n'
        ).encode()
        out = stream.feed(chunk)
        self.assertNotIn(b"rm -rf", out)

    def test_bad_index_is_dropped_in_enforce(self):
        screen = Screen(Path(tempfile.mkdtemp()), "enforce", "s")
        stream = StreamScreen(screen, "openai", "gpt", None)
        chunk = (
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":"not-an-int",'
            b'"function":{"name":"Bash","arguments":"rm"}}]}}]}\n\n'
        )
        out = stream.feed(chunk)
        self.assertEqual(out, b"")
        self.assertTrue(stream.blocked)

    def test_two_data_lines_are_both_seen(self):
        screen = Screen(Path(tempfile.mkdtemp()), "enforce", "s")
        stream = StreamScreen(screen, "openai", "gpt", None)
        chunk = (
            b'data: {"choices":[{"delta":{"content":"ok"}}]}\n'
            b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,'
            b'"function":{"name":"Bash","arguments":"{\\"command\\":\\"rm -rf /\\"}"}}]}}]}\n'
        )
        out = stream.feed(chunk)
        self.assertNotIn(b"rm -rf", out)
