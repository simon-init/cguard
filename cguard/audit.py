"""The audit log: one JSON line per decision, local only, secrets masked."""
import json
import time

from . import config, patterns


def record(entry):
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **entry}
    for key in ("what", "target", "command"):
        if key in entry and isinstance(entry[key], str):
            entry[key] = patterns.redact(entry[key])[:500]
    try:
        config.AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(config.AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def tail(n=20):
    try:
        lines = config.AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
