---
description: Show the last decisions cguard made in this and earlier sessions
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/cguard/cli.py" audit 30` and present the output as a short list, newest last. If the user asks about one entry, run `python3 "${CLAUDE_PLUGIN_ROOT}/cguard/cli.py" explain <rule>` for that entry's rule and summarise it in plain words.
