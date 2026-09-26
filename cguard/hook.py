#!/usr/bin/env python3
"""The hook entry point. Claude Code runs this before every Read, Edit, Write, Grep
and Bash call, and once at session start. It prints a decision as JSON or nothing.

Never crashes the tool call: on an internal error it logs and lets the call through.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cguard import audit, config, guards, patterns  # noqa: E402


BLOCKED = ("cguard: your message holds {label}{where} and was not sent. Claude Code erased it, and nothing left this machine.\n"
           "Remove the key and send the message again. The key is still in your terminal history and your clipboard.\n"
           "If it was pasted anywhere else, rotate it.\n"
           "To show a key on purpose: cguard set secrets.prompt ask, then set it back to deny.")
EXPOSED = ("cguard: the user's message holds {label}. The value is now in this transcript. In one line, tell the user "
           "that this key is exposed in the transcript and must be rotated. Do not repeat the value. Then continue "
           "with the task.")


def prompt_check(data, cfg, cwd):
    """A key pasted into the chat: stop the message (deny), or let it through and have Claude say
    that the key must be rotated (ask)."""
    mode = cfg["rules"].get("secrets.prompt", "deny")
    if mode == "off":
        return
    text = data.get("user_prompt") or data.get("prompt") or ""
    label = patterns.find_secret(text[:262144])
    if not label:
        return
    if cfg["audit"]["decisions"]:
        audit.record({"kind": "decision", "tool": "prompt", "rule": "secrets.prompt", "mode": mode,
                      "what": f"a message that holds {label}", "cwd": cwd, "target": label})
    if mode == "deny":
        line = next((i for i, one in enumerate(text.splitlines(), 1) if patterns.find_secret(one)), None)
        where = f" on line {line}" if line else ""
        sys.stderr.write(BLOCKED.format(label=label, where=where) + "\n")
        sys.exit(2)
    print(EXPOSED.format(label=label))


def main():
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return
    event = data.get("hook_event_name", "PreToolUse")
    cwd = data.get("cwd") or os.getcwd()
    try:
        cfg = config.load()
        if event == "UserPromptSubmit":
            prompt_check(data, cfg, cwd)
            return
        if event == "SessionStart":
            note = guards.session_check(cwd, cfg)
            if not config.CONFIG_PATH.exists():
                note = ("cguard is installed but not set up. Tell the user once, in one line, to run "
                        "`cguard setup` in a terminal, then continue.") + (" " + note if note else "")
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
