---
description: Explain the last refusal and the way forward
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/secret_guard/cli.py" why` and explain the result to the user in plain words. Say what was refused. Say why the rule exists. Give the two ways forward: they do it themselves, or they allow it. Do not retry the refused call unless the user changes the rule or the allowlist.
