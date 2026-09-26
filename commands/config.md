---
description: Show the current secret-guard configuration
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/secret_guard/cli.py" show` and present the output as it is.

Then tell the user four things. A rule is changed with `secret-guard set <rule> <deny|ask|off>`. An allowlist is changed with `secret-guard allow <list> <value>`. If they say so, you can run both for them. The full configuration screen with descriptions is `secret-guard config`, which they run themselves in a terminal, because it is interactive.
