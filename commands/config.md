---
description: Show the current cguard configuration
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/cguard/cli.py" show` and present the output as it is.

Then tell the user four things. A rule is changed with `cguard set <rule> <deny|ask|off>`. An allowlist is changed with `cguard allow <list> <value>`. If they say so, you can run both for them. The full configuration screen with descriptions is `cguard config`, which they run themselves in a terminal, because it is interactive.
