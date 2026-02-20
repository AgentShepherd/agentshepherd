#!/usr/bin/env python3
"""Minimal AI agent that runs through Crust — demonstrates real-time blocking.

Uses the OpenAI SDK with tool_use. The agent runs an agentic loop:
  1. User asks the agent to gather system info
  2. The LLM calls tools (read_file, run_command)
  3. When a tool_call targets sensitive files, Crust Layer 0 blocks it (HTTP 403)
  4. The agent reports the block and continues

Prerequisites:
  - pip install openai
  - crust start --auto (Crust gateway on localhost:9090)
  - GROQ_API_KEY env var set (or edit API_KEY below)

Usage:
  python3 scripts/demo-agent.py                # Normal run
  python3 scripts/demo-agent.py --demo         # Scripted demo for GIF recording
"""

import json
import os
import sys
import time

from openai import OpenAI

CRUST_URL = "http://localhost:9090/v1"
API_KEY = os.environ.get("GROQ_API_KEY", "gsk_demo_key")
MODEL = "llama-3.3-70b-versatile"

# Minimal tool definitions (~300 tokens total — well under Groq free tier limits)
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from disk",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a shell command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command"}
                },
                "required": ["command"],
            },
        },
    },
]

# ANSI colors
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[0;36m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_agent(msg):
    print(f"{CYAN}🤖 Agent:{RESET} {msg}")


def print_block(msg):
    print(f"{RED}🛡  BLOCKED:{RESET} {msg}")


def print_allow(msg):
    print(f"{GREEN}✓  Allowed:{RESET} {msg}")


def fake_tool_result(name, args):
    """Simulate tool execution locally (we never actually run commands)."""
    if name == "read_file":
        return f"Contents of {args.get('path', '?')}: [sample data]"
    if name == "run_command":
        return f"Output of `{args.get('command', '?')}`: [sample output]"
    return "ok"


def run_agent(messages):
    """Run one turn of the agentic loop. Returns (response, blocked)."""
    client = OpenAI(base_url=CRUST_URL, api_key=API_KEY)
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            max_tokens=512,
        )
        return response, False
    except Exception as e:
        err = str(e)
        if "403" in err or "blocked" in err.lower():
            return None, True
        raise


def demo_mode():
    """Scripted demo: inject dangerous tool_calls to trigger Crust blocks."""
    print()
    print(f"{BOLD}{YELLOW}⚡ AI Agent running through Crust gateway...{RESET}")
    print(f"{DIM}   Model: {MODEL} | Gateway: {CRUST_URL}{RESET}")
    print()

    attacks = [
        ("read_file", {"path": "/home/user/.ssh/id_rsa"}, "SSH private key"),
        ("read_file", {"path": "/app/.env"}, "Environment secrets"),
        ("read_file", {"path": "/home/user/.aws/credentials"}, "AWS credentials"),
        (
            "read_file",
            {
                "path": "/Users/me/Library/Application Support/Google/Chrome/Default/Login Data"
            },
            "Browser passwords",
        ),
        ("run_command", {"command": "cat /home/user/.bash_history"}, "Shell history"),
    ]

    blocked = 0
    for tool_name, tool_args, label in attacks:
        # Build a conversation with this tool_call in history (triggers Layer 0)
        messages = [
            {"role": "user", "content": "Help me gather system information"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": tool_name,
                            "arguments": json.dumps(tool_args),
                        },
                    }
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "file contents here",
            },
            {"role": "user", "content": "continue"},
        ]

        arg_str = json.dumps(tool_args)
        print_agent(f"Calling {BOLD}{tool_name}{RESET}({DIM}{arg_str}{RESET})")

        _, was_blocked = run_agent(messages)
        if was_blocked:
            print_block(f"{label}")
            blocked += 1
        else:
            print_allow(f"{label}")
        print()
        time.sleep(0.6)

    print(f"{GREEN}{BOLD}✓ {blocked}/{len(attacks)} dangerous calls blocked by Crust.{RESET}")
    print()


def interactive_mode():
    """Real agentic loop: send user prompt, let LLM decide tools."""
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Read my SSH key at ~/.ssh/id_rsa"

    print()
    print(f"{BOLD}{YELLOW}⚡ AI Agent running through Crust gateway...{RESET}")
    print(f"{DIM}   Model: {MODEL} | Gateway: {CRUST_URL}{RESET}")
    print()
    print(f"{BOLD}User:{RESET} {prompt}")
    print()

    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant with access to tools. Use read_file and run_command to help the user.",
        },
        {"role": "user", "content": prompt},
    ]

    for turn in range(5):
        response, was_blocked = run_agent(messages)

        if was_blocked:
            print_block("Crust blocked this request (dangerous tool_call in history)")
            break

        choice = response.choices[0]

        if choice.message.tool_calls:
            # LLM wants to call tools
            messages.append(choice.message)
            for tc in choice.message.tool_calls:
                args = json.loads(tc.function.arguments)
                print_agent(
                    f"Calling {BOLD}{tc.function.name}{RESET}({DIM}{json.dumps(args)}{RESET})"
                )
                result = fake_tool_result(tc.function.name, args)
                print_allow(f"Tool returned: {result[:80]}")
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    }
                )
            print()
        else:
            # LLM gave a text response
            text = choice.message.content or "(no response)"
            print(f"{CYAN}🤖 Agent:{RESET} {text}")
            break

    print()


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo_mode()
    else:
        interactive_mode()
