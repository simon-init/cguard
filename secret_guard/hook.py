#!/usr/bin/env python3
"""The hook entry point. Claude Code runs this before every Read, Edit, Write, Grep
and Bash call, and once at session start. It prints a decision as JSON or nothing.

Never crashes the tool call: on an internal error it logs and lets the call through.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secret_guard import audit, config, guards  # noqa: E402


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return
    event = data.get("hook_event_name", "PreToolUse")
    cwd = data.get("cwd") or os.getcwd()
    try:
        cfg = config.load()
        if event == "SessionStart":
            note = guards.session_check(cwd, cfg)
            if note:
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": note}}))
            return
        decision = guards.evaluate(data, cfg)
        tool = data.get("tool_name", "")
        if cfg["audit"]["commands"] and tool == "Bash":
            audit.record({"kind": "command", "tool": tool, "cwd": cwd,
                          "command": (data.get("tool_input") or {}).get("command", "")})
        if not decision:
            return
        if cfg["audit"]["decisions"]:
            tool_input = data.get("tool_input") or {}
            audit.record({"kind": "decision", "tool": tool, "rule": decision.rule, "mode": decision.mode,
                          "what": decision.what, "cwd": cwd,
                          "target": tool_input.get("file_path") or tool_input.get("path") or tool_input.get("command", "")})
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "permissionDecision": decision.mode,
                                                 "permissionDecisionReason": decision.reason()}}))
    except Exception as exc:  # a broken guard must not break the session
        audit.record({"kind": "error", "error": repr(exc)[:300], "cwd": cwd})
        return


if __name__ == "__main__":
    main()
