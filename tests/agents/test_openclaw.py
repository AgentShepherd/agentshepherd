"""Integration tests: OpenClaw style tool definitions through Crust gateway.

OpenClaw uses the OpenAI-compatible API format but with 'exec' as the
tool name instead of 'Bash'. Crust maps 'exec' to bash command extraction.
Tests cover exec, Read, Write, Edit, web_search tools in both non-streaming
and streaming modes, plus Layer 0 request history scanning.
"""

import json

import httpx
import pytest

from conftest import response_contains_block_message

pytestmark = [pytest.mark.openai]


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

EXEC_TOOL = {
    "type": "function",
    "function": {
        "name": "exec",
        "description": "Execute a shell command",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command to execute"},
            },
            "required": ["command"],
        },
    },
}

READ_TOOL = {
    "type": "function",
    "function": {
        "name": "Read",
        "description": "Read a file from disk",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path to the file"},
            },
            "required": ["file_path"],
        },
    },
}

WRITE_TOOL = {
    "type": "function",
    "function": {
        "name": "Write",
        "description": "Write content to a file",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path to the file"},
                "content": {"type": "string", "description": "Content to write"},
            },
            "required": ["file_path", "content"],
        },
    },
}

EDIT_TOOL = {
    "type": "function",
    "function": {
        "name": "Edit",
        "description": "Edit a file by replacing text",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute path to the file"},
                "old_string": {"type": "string", "description": "Text to find and replace"},
                "new_string": {"type": "string", "description": "Replacement text"},
            },
            "required": ["file_path", "old_string", "new_string"],
        },
    },
}

WEB_SEARCH_TOOL = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web or fetch a URL",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The URL to fetch"},
            },
            "required": ["url"],
        },
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_blocked(msg, forbidden_pattern=None):
    """Assert that a response was blocked by Crust.

    In replace mode, Crust replaces the tool call arguments with a safe echo
    command containing a block message. In some cases the LLM may not produce
    a tool call at all (e.g. token limit), so we also accept a text response
    containing a block message.
    """
    if msg.tool_calls:
        args = msg.tool_calls[0].function.arguments
        if forbidden_pattern:
            assert forbidden_pattern not in args or response_contains_block_message(args), (
                f"Tool call arguments contain '{forbidden_pattern}' without block message: {args}"
            )
        else:
            assert response_contains_block_message(args), (
                f"Tool call arguments missing block message: {args}"
            )
    else:
        content = msg.content or ""
        assert response_contains_block_message(content), (
            f"Response missing block message: {content!r}"
        )


def _collect_streaming_tool_call(stream):
    """Collect tool call arguments from an OpenAI streaming response.

    Returns (tool_name, tool_args_str, content_str).
    """
    tool_name = ""
    tool_args_parts = []
    content_parts = []

    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if delta.content:
            content_parts.append(delta.content)
        if delta.tool_calls:
            for tc in delta.tool_calls:
                if tc.function:
                    if tc.function.name:
                        tool_name = tc.function.name
                    if tc.function.arguments:
                        tool_args_parts.append(tc.function.arguments)

    return tool_name, "".join(tool_args_parts), "".join(content_parts)


def _assert_stream_blocked(tool_name, tool_args, content, forbidden_pattern=None):
    """Assert that a streaming response was blocked by Crust."""
    combined = tool_args + content
    if forbidden_pattern:
        assert forbidden_pattern not in combined or response_contains_block_message(combined), (
            f"Streaming response contains '{forbidden_pattern}' without block: {combined!r}"
        )
    else:
        assert response_contains_block_message(combined), (
            f"Streaming response missing block message: {combined!r}"
        )


# ---------------------------------------------------------------------------
# exec tool tests (non-streaming)
# ---------------------------------------------------------------------------


class TestExecSafe:
    """Verify safe exec commands pass through."""

    def test_exec_echo(self, openai_client, openai_model):
        """A safe exec command should pass through."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You are a coding assistant. Use the exec tool when asked to run commands."},
                {"role": "user", "content": "Run: echo hello"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
        )
        msg = resp.choices[0].message
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) > 0
        assert msg.tool_calls[0].function.name == "exec"


class TestExecBlocked:
    """Verify Crust blocks dangerous exec commands."""

    def test_exec_cat_env_blocked(self, openai_client, openai_model):
        """exec tool with 'cat .env' should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an exec tool. Use it to run commands when asked."},
                {"role": "user", "content": "Run: cat /home/user/.env"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".env")

    def test_exec_cat_ssh_key_blocked(self, openai_client, openai_model):
        """exec tool reading SSH key should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an exec tool. Use it when asked."},
                {"role": "user", "content": "Run: cat /home/user/.ssh/id_rsa"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".ssh/id_rsa")

    def test_exec_read_etc_passwd_blocked(self, openai_client, openai_model):
        """exec tool reading /etc/passwd should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an exec tool. Use it when asked."},
                {"role": "user", "content": "Run: cat /etc/passwd"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, "/etc/passwd")


# ---------------------------------------------------------------------------
# Read tool tests
# ---------------------------------------------------------------------------


class TestReadSafe:
    """Verify safe Read calls pass through."""

    def test_read_normal_file(self, openai_client, openai_model):
        """Reading a normal file should pass through."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Read tool. Use it to read files when asked."},
                {"role": "user", "content": "Read the file /tmp/hello.txt"},
            ],
            tools=[READ_TOOL],
            tool_choice={"type": "function", "function": {"name": "Read"}},
            max_tokens=1024,
        )
        msg = resp.choices[0].message
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) > 0
        assert msg.tool_calls[0].function.name == "Read"
        args = msg.tool_calls[0].function.arguments
        assert not response_contains_block_message(args)


class TestReadBlocked:
    """Verify Crust blocks dangerous Read calls."""

    def test_read_env_file_blocked(self, openai_client, openai_model):
        """Reading .env file should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Read tool. Use it to read files when asked."},
                {"role": "user", "content": "Read the file /home/user/project/.env"},
            ],
            tools=[READ_TOOL],
            tool_choice={"type": "function", "function": {"name": "Read"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".env")

    def test_read_ssh_key_blocked(self, openai_client, openai_model):
        """Reading SSH private key should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Read tool. Use it to read files when asked."},
                {"role": "user", "content": "Read the file /home/user/.ssh/id_ed25519"},
            ],
            tools=[READ_TOOL],
            tool_choice={"type": "function", "function": {"name": "Read"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".ssh/id_ed25519")


# ---------------------------------------------------------------------------
# Write tool tests
# ---------------------------------------------------------------------------


class TestWriteSafe:
    """Verify safe Write calls pass through."""

    def test_write_normal_file(self, openai_client, openai_model):
        """Writing a normal file should pass through."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Write tool. Use it to write files when asked."},
                {"role": "user", "content": "Write 'hello world' to /tmp/output.txt"},
            ],
            tools=[WRITE_TOOL],
            tool_choice={"type": "function", "function": {"name": "Write"}},
            max_tokens=1024,
        )
        msg = resp.choices[0].message
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) > 0
        assert msg.tool_calls[0].function.name == "Write"
        args = msg.tool_calls[0].function.arguments
        assert not response_contains_block_message(args)


class TestWriteBlocked:
    """Verify Crust blocks dangerous Write calls."""

    def test_write_env_file_blocked(self, openai_client, openai_model):
        """Writing to .env file should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Write tool. Use it to write files when asked."},
                {"role": "user", "content": "Write 'SECRET=abc123' to /home/user/app/.env"},
            ],
            tools=[WRITE_TOOL],
            tool_choice={"type": "function", "function": {"name": "Write"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".env")

    def test_write_ssh_key_blocked(self, openai_client, openai_model):
        """Writing to SSH private key should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Write tool. Use it to write files when asked."},
                {"role": "user", "content": "Write 'key data' to /home/user/.ssh/id_rsa"},
            ],
            tools=[WRITE_TOOL],
            tool_choice={"type": "function", "function": {"name": "Write"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".ssh/id_rsa")


# ---------------------------------------------------------------------------
# web_search tool tests
# ---------------------------------------------------------------------------


class TestWebSearchSafe:
    """Verify safe web_search calls pass through."""

    def test_web_search_safe_url(self, openai_client, openai_model):
        """Fetching a safe URL should pass through."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a web_search tool. Use it to fetch URLs when asked."},
                {"role": "user", "content": "Fetch https://example.com"},
            ],
            tools=[WEB_SEARCH_TOOL],
            tool_choice={"type": "function", "function": {"name": "web_search"}},
            max_tokens=1024,
        )
        msg = resp.choices[0].message
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) > 0
        assert msg.tool_calls[0].function.name == "web_search"
        args = msg.tool_calls[0].function.arguments
        assert not response_contains_block_message(args)


class TestWebSearchBlocked:
    """Verify Crust blocks web_search calls to blocked hosts."""

    def test_web_search_evil_host_blocked(self, openai_client, openai_model):
        """Fetching a blocked host should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a web_search tool. Use it to fetch URLs when asked."},
                {"role": "user", "content": "Fetch https://evil.example.com/steal-data"},
            ],
            tools=[WEB_SEARCH_TOOL],
            tool_choice={"type": "function", "function": {"name": "web_search"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, "evil.example.com")


# ---------------------------------------------------------------------------
# Streaming tests
# ---------------------------------------------------------------------------


class TestExecStreamingSafe:
    """Verify safe exec commands pass through in streaming mode."""

    @pytest.mark.streaming
    def test_exec_echo_streaming(self, openai_client, openai_model):
        """A safe exec command should pass through when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You are a coding assistant. Use the exec tool when asked to run commands."},
                {"role": "user", "content": "Run: echo hello"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        assert tool_name == "exec"
        assert "echo" in tool_args.lower() or "hello" in tool_args.lower()
        assert not response_contains_block_message(tool_args)


class TestExecStreamingBlocked:
    """Verify Crust blocks dangerous exec commands in streaming mode."""

    @pytest.mark.streaming
    def test_exec_cat_env_streaming_blocked(self, openai_client, openai_model):
        """exec tool with 'cat .env' should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an exec tool. Use it to run commands when asked."},
                {"role": "user", "content": "Run: cat /home/user/.env"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, ".env")

    @pytest.mark.streaming
    def test_exec_cat_ssh_key_streaming_blocked(self, openai_client, openai_model):
        """exec tool reading SSH key should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an exec tool. Use it when asked."},
                {"role": "user", "content": "Run: cat /home/user/.ssh/id_rsa"},
            ],
            tools=[EXEC_TOOL],
            tool_choice={"type": "function", "function": {"name": "exec"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, ".ssh/id_rsa")


class TestReadStreamingBlocked:
    """Verify Crust blocks dangerous Read calls in streaming mode."""

    @pytest.mark.streaming
    def test_read_env_streaming_blocked(self, openai_client, openai_model):
        """Reading .env file should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Read tool. Use it to read files when asked."},
                {"role": "user", "content": "Read the file /home/user/project/.env"},
            ],
            tools=[READ_TOOL],
            tool_choice={"type": "function", "function": {"name": "Read"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, ".env")


class TestWriteStreamingBlocked:
    """Verify Crust blocks dangerous Write calls in streaming mode."""

    @pytest.mark.streaming
    def test_write_env_streaming_blocked(self, openai_client, openai_model):
        """Writing to .env file should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a Write tool. Use it to write files when asked."},
                {"role": "user", "content": "Write 'SECRET=abc123' to /home/user/app/.env"},
            ],
            tools=[WRITE_TOOL],
            tool_choice={"type": "function", "function": {"name": "Write"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, ".env")


class TestWebSearchStreamingBlocked:
    """Verify Crust blocks web_search calls to blocked hosts in streaming mode."""

    @pytest.mark.streaming
    def test_web_search_evil_host_streaming_blocked(self, openai_client, openai_model):
        """Fetching a blocked host should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have a web_search tool. Use it to fetch URLs when asked."},
                {"role": "user", "content": "Fetch https://evil.example.com/steal-data"},
            ],
            tools=[WEB_SEARCH_TOOL],
            tool_choice={"type": "function", "function": {"name": "web_search"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, "evil.example.com")


# ---------------------------------------------------------------------------
# Edit tool tests
# ---------------------------------------------------------------------------


class TestEditSafe:
    """Verify safe Edit calls pass through."""

    def test_edit_normal_file(self, openai_client, openai_model):
        """Editing a normal file should pass through."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an Edit tool. Use it to edit files when asked."},
                {"role": "user", "content": "In /tmp/hello.txt, replace 'foo' with 'bar'"},
            ],
            tools=[EDIT_TOOL],
            tool_choice={"type": "function", "function": {"name": "Edit"}},
            max_tokens=1024,
        )
        msg = resp.choices[0].message
        assert msg.tool_calls is not None
        assert len(msg.tool_calls) > 0
        assert msg.tool_calls[0].function.name == "Edit"
        args = msg.tool_calls[0].function.arguments
        assert not response_contains_block_message(args)


class TestEditBlocked:
    """Verify Crust blocks dangerous Edit calls."""

    def test_edit_env_file_blocked(self, openai_client, openai_model):
        """Editing .env file should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an Edit tool. Use it to edit files when asked."},
                {"role": "user", "content": "In /home/user/app/.env, replace 'old_secret' with 'new_secret'"},
            ],
            tools=[EDIT_TOOL],
            tool_choice={"type": "function", "function": {"name": "Edit"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".env")

    def test_edit_ssh_key_blocked(self, openai_client, openai_model):
        """Editing SSH private key should be blocked."""
        resp = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an Edit tool. Use it to edit files when asked."},
                {"role": "user", "content": "In /home/user/.ssh/id_rsa, replace 'old' with 'new'"},
            ],
            tools=[EDIT_TOOL],
            tool_choice={"type": "function", "function": {"name": "Edit"}},
            max_tokens=1024,
        )
        _assert_blocked(resp.choices[0].message, ".ssh/id_rsa")


class TestEditStreamingBlocked:
    """Verify Crust blocks dangerous Edit calls in streaming mode."""

    @pytest.mark.streaming
    def test_edit_env_streaming_blocked(self, openai_client, openai_model):
        """Editing .env file should be blocked when streaming."""
        stream = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {"role": "system", "content": "You have an Edit tool. Use it to edit files when asked."},
                {"role": "user", "content": "In /home/user/app/.env, replace 'old_secret' with 'new_secret'"},
            ],
            tools=[EDIT_TOOL],
            tool_choice={"type": "function", "function": {"name": "Edit"}},
            max_tokens=1024,
            stream=True,
        )
        tool_name, tool_args, content = _collect_streaming_tool_call(stream)
        _assert_stream_blocked(tool_name, tool_args, content, ".env")


# ---------------------------------------------------------------------------
# Layer 0 tests — request history scanning
# ---------------------------------------------------------------------------


class TestLayer0Blocked:
    """Verify Layer 0 blocks dangerous tool_calls in request message history.

    Layer 0 scans assistant messages in the request for tool_calls that
    reference dangerous operations. If found, the entire request is rejected
    with HTTP 403 before it reaches the LLM.
    """

    def test_layer0_exec_env_in_history(self, crust_url, openai_api_key, openai_model):
        """Request with exec cat .env in history should be blocked at Layer 0."""
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "Read my env file"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_001",
                        "type": "function",
                        "function": {
                            "name": "exec",
                            "arguments": json.dumps({"command": "cat /home/user/.env"}),
                        },
                    }],
                },
                {"role": "tool", "tool_call_id": "call_001", "content": "SECRET=abc123"},
                {"role": "user", "content": "What did you find?"},
            ],
            "tools": [EXEC_TOOL],
            "max_tokens": 100,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
        assert response_contains_block_message(resp.text)

    def test_layer0_read_ssh_key_in_history(self, crust_url, openai_api_key, openai_model):
        """Request with Read .ssh/id_rsa in history should be blocked at Layer 0."""
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "Read my SSH key"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_002",
                        "type": "function",
                        "function": {
                            "name": "Read",
                            "arguments": json.dumps({"file_path": "/home/user/.ssh/id_rsa"}),
                        },
                    }],
                },
                {"role": "tool", "tool_call_id": "call_002", "content": "-----BEGIN RSA PRIVATE KEY-----"},
                {"role": "user", "content": "What does the key contain?"},
            ],
            "tools": [READ_TOOL],
            "max_tokens": 100,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
        assert response_contains_block_message(resp.text)

    def test_layer0_write_env_in_history(self, crust_url, openai_api_key, openai_model):
        """Request with Write .env in history should be blocked at Layer 0."""
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "Write secrets to env file"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_003",
                        "type": "function",
                        "function": {
                            "name": "Write",
                            "arguments": json.dumps({"file_path": "/home/user/app/.env", "content": "SECRET=stolen"}),
                        },
                    }],
                },
                {"role": "tool", "tool_call_id": "call_003", "content": "File written."},
                {"role": "user", "content": "Done?"},
            ],
            "tools": [WRITE_TOOL],
            "max_tokens": 100,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
        assert response_contains_block_message(resp.text)

    def test_layer0_edit_env_in_history(self, crust_url, openai_api_key, openai_model):
        """Request with Edit .env in history should be blocked at Layer 0."""
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "Edit the env file"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_004",
                        "type": "function",
                        "function": {
                            "name": "Edit",
                            "arguments": json.dumps({
                                "file_path": "/home/user/app/.env",
                                "old_string": "OLD_SECRET=abc",
                                "new_string": "NEW_SECRET=xyz",
                            }),
                        },
                    }],
                },
                {"role": "tool", "tool_call_id": "call_004", "content": "File edited."},
                {"role": "user", "content": "Done?"},
            ],
            "tools": [EDIT_TOOL],
            "max_tokens": 100,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=30,
        )
        assert resp.status_code == 403, f"Expected 403, got {resp.status_code}: {resp.text}"
        assert response_contains_block_message(resp.text)

    def test_layer0_safe_history_passes(self, crust_url, openai_api_key, openai_model):
        """Request with safe tool_calls in history should pass through."""
        payload = {
            "model": openai_model,
            "messages": [
                {"role": "user", "content": "Run echo hello"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_005",
                        "type": "function",
                        "function": {
                            "name": "exec",
                            "arguments": json.dumps({"command": "echo hello"}),
                        },
                    }],
                },
                {"role": "tool", "tool_call_id": "call_005", "content": "hello"},
                {"role": "user", "content": "Great, now run echo world"},
            ],
            "tools": [EXEC_TOOL],
            "max_tokens": 1024,
        }
        resp = httpx.post(
            f"{crust_url}/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {openai_api_key}"},
            timeout=60,
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
