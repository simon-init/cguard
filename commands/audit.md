---
description: Show the last decisions secret-guard made in this and earlier sessions
---

Run `python3 "${CLAUDE_PLUGIN_ROOT}/secret_guard/cli.py" audit 30` and present the output as a short list, newest last. If the user asks about one entry, run `python3 "${CLAUDE_PLUGIN_ROOT}/secret_guard/cli.py" explain <rule>` for that entry's rule and summarise it in plain words.
