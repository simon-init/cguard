---
description: Explain the last blocked action and the safe alternative
---

Run `"${CLAUDE_PLUGIN_ROOT}/bin/cguard" why` and explain the result to the user in plain words. Say what was refused. Say why the rule exists. Give the two ways forward: they do it themselves, or they allow it. Do not retry the refused call unless the user changes the rule or the allowlist.
