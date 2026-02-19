"""Property-based fuzzing: random payloads through Crust HTTP proxy.

Uses hypothesis to generate mutated payloads and verify invariants:
- Mutations of sensitive paths must always be blocked
- Random tool names with sensitive field values must be blocked
- Safe payloads must never be blocked (no false positives)
- JSON unicode escapes of blocked payloads must still be blocked
- Random field casing must still be blocked
"""

import json
import random
import string

import httpx
import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck

from conftest import make_layer0_payload, response_contains_block_message

pytestmark = [pytest.mark.fuzz]


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [".env", ".ssh/id_rsa", ".ssh/id_ed25519"]
SENSITIVE_ABSOLUTE = ["/etc/passwd"]
TRAVERSAL_SEGMENTS = ["../", "./", "//", "/../"]
SAFE_COMMANDS = ["echo", "ls", "pwd", "date", "whoami", "uname"]
SAFE_PATHS = ["/tmp/file.txt", "/tmp/hello", "/var/log/test.log"]


# Common absolute prefixes to prepend before traversal back to sensitive files
_ABS_PREFIXES = ["/tmp", "/var/log", "/opt", "/usr/local", "/tmp/foo/bar"]


@st.composite
def traversal_mutated_paths(draw):
    """Generate absolute paths that traverse back to sensitive files.

    E.g. /tmp/../home/user/.env, /var/log/../../etc/passwd
    """
    base = draw(st.sampled_from(SENSITIVE_PATHS + SENSITIVE_ABSOLUTE))
    prefix = draw(st.sampled_from(_ABS_PREFIXES))
    n_segments = draw(st.integers(min_value=1, max_value=4))
    traversal = "/".join([".."] * (prefix.count("/") + n_segments))

    if base.startswith("/"):
        # Absolute sensitive path: /tmp/../../etc/passwd
        return f"{prefix}/{traversal}{base}"
    else:
        # Relative sensitive path (.env, .ssh/id_rsa): /tmp/../home/user/.env
        return f"{prefix}/{traversal}/home/user/{base}"


@st.composite
def random_tool_names(draw):
    """Generate random plausible tool names."""
    prefixes = ["my_", "custom_", "agent_", "run_", "do_", ""]
    suffixes = ["exec", "cmd", "run", "shell", "tool", "action", "op"]
    prefix = draw(st.sampled_from(prefixes))
    suffix = draw(st.sampled_from(suffixes))
    return prefix + suffix


@st.composite
def safe_command_payloads(draw):
    """Generate commands that should never be blocked."""
    cmd = draw(st.sampled_from(SAFE_COMMANDS))
    arg = draw(st.sampled_from(["hello", "world", "-l", "-a", "/tmp", "."]))
    return f"{cmd} {arg}"


def _apply_json_unicode_escapes(s, positions):
    """Replace characters at given positions with \\uXXXX escapes."""
    chars = list(s)
    result = []
    for i, ch in enumerate(chars):
        if i in positions and ord(ch) < 0x80:
            result.append(f"\\u{ord(ch):04x}")
        else:
            result.append(ch)
    return "".join(result)


@st.composite
def json_escaped_commands(draw):
    """Take a known-blocked command and apply random JSON unicode escapes."""
    commands = [
        "cat /home/user/.env",
        "cat /home/user/.ssh/id_rsa",
        "cat /etc/passwd",
    ]
    cmd = draw(st.sampled_from(commands))
    # Pick 1-5 random positions to escape
    n_positions = draw(st.integers(min_value=1, max_value=min(5, len(cmd))))
    positions = draw(st.lists(
        st.integers(min_value=0, max_value=len(cmd) - 1),
        min_size=n_positions, max_size=n_positions, unique=True,
    ))
    return _apply_json_unicode_escapes(cmd, set(positions))


FIELD_NAMES = ["command", "Command", "COMMAND", "cmd", "CMD"]
PATH_FIELD_NAMES = ["file_path", "File_Path", "FILE_PATH", "path", "Path", "PATH"]


@st.composite
def case_varied_exec_fields(draw):
    """Generate exec-like arguments with random field name casing."""
    field = draw(st.sampled_from(FIELD_NAMES))
    path = draw(st.sampled_from([
        "cat /home/user/.env",
        "cat /home/user/.ssh/id_rsa",
        "cat /etc/passwd",
    ]))
    return {field: path}


@st.composite
def case_varied_read_fields(draw):
    """Generate read-like arguments with random field name casing."""
    field = draw(st.sampled_from(PATH_FIELD_NAMES))
    path = draw(st.sampled_from([
        "/home/user/.env",
        "/home/user/.ssh/id_rsa",
        "/etc/passwd",
    ]))
    return {field: path}


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------

# Increase deadline — each test makes an HTTP roundtrip
FUZZ_SETTINGS = dict(max_examples=200, deadline=30000,
                     suppress_health_check=[HealthCheck.too_slow])


class TestFuzzPathMutations:
    """Mutated sensitive paths must always be blocked."""

    @settings(**FUZZ_SETTINGS)
    @given(path=traversal_mutated_paths())
    def test_traversal_mutations_blocked(self, crust_url, openai_api_key, openai_model, path):
        payload = make_layer0_payload(openai_model, "exec", f"cat {path}")
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for path {path!r}, got {resp.status_code}"
        )

    @settings(**FUZZ_SETTINGS)
    @given(path=traversal_mutated_paths())
    def test_read_traversal_mutations_blocked(self, crust_url, openai_api_key, openai_model, path):
        payload = make_layer0_payload(openai_model, "Read", {"file_path": path})
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for Read path {path!r}, got {resp.status_code}"
        )


class TestFuzzToolNameVariations:
    """Random tool names + sensitive fields must be blocked by shape detection."""

    @settings(**FUZZ_SETTINGS)
    @given(tool_name=random_tool_names())
    def test_random_tool_command_field_blocked(self, crust_url, openai_api_key, openai_model, tool_name):
        arguments = {"command": "cat /home/user/.env"}
        tools = [{
            "type": "function",
            "function": {
                "name": tool_name,
                "parameters": {"type": "object", "properties": {}},
            },
        }]
        payload = make_layer0_payload(openai_model, tool_name, arguments, tools=tools)
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for tool {tool_name!r}, got {resp.status_code}"
        )

    @settings(**FUZZ_SETTINGS)
    @given(tool_name=random_tool_names())
    def test_random_tool_path_field_blocked(self, crust_url, openai_api_key, openai_model, tool_name):
        arguments = {"file_path": "/home/user/.env"}
        tools = [{
            "type": "function",
            "function": {
                "name": tool_name,
                "parameters": {"type": "object", "properties": {}},
            },
        }]
        payload = make_layer0_payload(openai_model, tool_name, arguments, tools=tools)
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for tool {tool_name!r} with path field, got {resp.status_code}"
        )


class TestFuzzSafePayloads:
    """Random safe commands must never be blocked (no false positives)."""

    @settings(**FUZZ_SETTINGS)
    @given(cmd=safe_command_payloads())
    def test_safe_commands_pass(self, crust_url, openai_api_key, openai_model, cmd):
        payload = make_layer0_payload(openai_model, "exec", cmd)
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=60,
        )
        assert resp.status_code != 403, (
            f"Safe command {cmd!r} was incorrectly blocked"
        )

    @settings(**FUZZ_SETTINGS)
    @given(path=st.sampled_from(SAFE_PATHS))
    def test_safe_reads_pass(self, crust_url, openai_api_key, openai_model, path):
        payload = make_layer0_payload(openai_model, "Read", {"file_path": path})
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=60,
        )
        assert resp.status_code != 403, (
            f"Safe read path {path!r} was incorrectly blocked"
        )


class TestFuzzJSONEncoding:
    """JSON unicode escapes of blocked commands must still be blocked."""

    @settings(**FUZZ_SETTINGS)
    @given(escaped_cmd=json_escaped_commands())
    def test_json_escaped_commands_blocked(self, crust_url, openai_api_key, openai_model, escaped_cmd):
        # Build raw JSON args string with the pre-escaped command
        raw_args = '{"command": "' + escaped_cmd + '"}'
        tools = [{
            "type": "function",
            "function": {
                "name": "exec",
                "parameters": {"type": "object", "properties": {}},
            },
        }]
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "do it"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_fuzz_json",
                        "type": "function",
                        "function": {"name": "exec", "arguments": raw_args},
                    }],
                },
                {"role": "tool", "tool_call_id": "call_fuzz_json", "content": "done"},
                {"role": "user", "content": "what happened?"},
            ],
            "tools": tools,
            "max_tokens": 100,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for JSON-escaped {escaped_cmd!r}, got {resp.status_code}"
        )


class TestFuzzFieldCasing:
    """Random case variations of field names must still be blocked."""

    @settings(**FUZZ_SETTINGS)
    @given(args=case_varied_exec_fields())
    def test_exec_field_casing_blocked(self, crust_url, openai_api_key, openai_model, args):
        payload = make_layer0_payload(openai_model, "exec", args)
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for field casing {args!r}, got {resp.status_code}"
        )

    @settings(**FUZZ_SETTINGS)
    @given(args=case_varied_read_fields())
    def test_read_field_casing_blocked(self, crust_url, openai_api_key, openai_model, args):
        payload = make_layer0_payload(openai_model, "Read", args)
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, (
            f"Expected 403 for Read field casing {args!r}, got {resp.status_code}"
        )
