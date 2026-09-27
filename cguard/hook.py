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


BLOCKED = ("cguard: your message holds {label} and was not sent. Claude Code erased it, and nothing left this machine.\n"
           "Where: {where}\n"
           "Remove the key from that line and send the message again. The key is still in your terminal history and your clipboard.\n"
           "If it was pasted anywhere else, rotate it.\n"
           "To show a key on purpose: cguard set secrets.prompt ask, then set it back to deny.")
EXPOSED = ("cguard: the user's message holds {label}. The value is now in this transcript. In one line, tell the user "
           "that this key is exposed in the transcript and must be rotated. Do not repeat the value. Then continue "
           "with the task.")


def _excerpt(line, limit=56):
    """The start of the line with every secret cut out, so the user recognises the line
    without seeing the value again."""
    text = line
    for pattern, _label in patterns.PREFIXED:
        text = pattern.sub("[secret]", text)
    for pattern, _rid, _minimum, _group in patterns.GITLEAKS:
        text = pattern.sub("[secret]", text)
    for m in reversed(list(patterns.GENERIC.finditer(text))):
        text = text[:m.start(2)] + "[secret]" + text[m.end(2):]
    text = text.strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def _where(text):
    """The line the secret is on, by number and by its own first words. Inside a pasted block
    the number counts from the block's first line, because that is the text the user pasted;
    the wrapper Claude Code adds around a paste is not."""
    lines = text.splitlines()
    hit = next((i for i, one in enumerate(lines) if patterns.find_secret(one)), None)
    if hit is None:
        return "in the message"
    opening = next((j for j in range(hit, -1, -1) if lines[j].lstrip().startswith("<pasted_content")), None)
    number = f"line {hit - opening} of the pasted text" if opening is not None else f"line {hit + 1}"
    return f"{number}, the one that starts `{_excerpt(lines[hit])}`"


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
        where = _where(text)
        # As JSON with exit 0, not as exit code 2: the manifest runs `python3 ... || python ...`
        # for Windows, and a non-zero exit from the first would start the fallback and turn
        # the block into a pass.
        reason = BLOCKED.format(label=label, where=where)
        print(json.dumps({"decision": "block", "reason": reason,
                          "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "decision": "block", "reason": reason}}))
        return
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
