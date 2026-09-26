#!/usr/bin/env python3
"""Import the fixed-prefix secret formats from the gitleaks rule set.

    python3 tools/sync_gitleaks.py                # fetch from GitHub and regenerate
    python3 tools/sync_gitleaks.py path/to/gitleaks.toml [--show-skipped]

gitleaks (MIT, Zachary Rice and contributors) maintains about 250 rules. This script keeps
the ones whose regex begins with a fixed literal, such as ghp_ or AKIA, because a hook that
blocks work cannot afford the generic ones, and writes them to cguard/rules_gitleaks.py.
Rules that Python's re cannot compile, or that gitleaks names "generic", are skipped.
The license notice travels in THIRD_PARTY_LICENSES.md.
"""
import re
import sys
import time
import tomllib
import urllib.request
from pathlib import Path

SOURCE = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
OUT = Path(__file__).resolve().parent.parent / "cguard" / "rules_gitleaks.py"

POSIX = {"[:alnum:]": "A-Za-z0-9", "[:alpha:]": "A-Za-z", "[:digit:]": "0-9", "[:xdigit:]": "0-9A-Fa-f",
         "[:space:]": r"\s", "[:upper:]": "A-Z", "[:lower:]": "a-z", "[:word:]": r"\w", "[:punct:]": r"!-/:-@\[-`{-~"}

# Things a regex may start with that do not count as its prefix.
LEADING = re.compile(r"^(?:\(\?i\)|\(\?i:|\\b|\(\?:\^\|[^)]*\)|\(\?<![^)]*\)|\(\?:\\b\|[^)]*\)|\(\?:\^\|\\W\)|\((?!\?))+")
# A literal run (dots escaped), or an alternation of literals, at the very start.
LIT = r"(?:[A-Za-z0-9_\-]|\\\.)"
PREFIX = re.compile(r"^(?:" + LIT + r"{3,}|\(\?:(?:" + LIT + r"{2,}\|)+" + LIT + r"{2,}\)" + LIT + r"*)")


def to_python(regex):
    for k, v in POSIX.items():
        regex = regex.replace(k, v)
    # Go allows (?i) anywhere and applies it to the rest; Python wants it at the start.
    # Moving it to the front makes the whole rule case-insensitive, which for a fixed
    # prefix is a little more permissive and never less.
    if "(?i)" in regex[1:]:
        regex = "(?i)" + regex.replace("(?i)", "")
    return regex


def branches(body):
    """Split at the alternation bars of the outermost group, up to its closing paren."""
    depth, in_class, out, cur, i = 0, False, [], "", 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            cur += body[i:i + 2]; i += 2; continue
        if in_class:
            in_class = ch != "]"
        elif ch == "[":
            in_class = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        elif ch == "|" and depth == 0:
            out.append(cur); cur = ""; i += 1; continue
        cur += ch; i += 1
    out.append(cur)
    return out


def has_fixed_prefix(regex):
    """Every branch of the outermost group starts with a literal, or the rule is out."""
    body = LEADING.sub("", regex)
    return all(PREFIX.match(b) for b in branches(body))


def literal(rule):
    """One tuple as source. The regex is written as two adjacent strings, split inside its
    first literal run, so the generated file does not match its own rules when scanned."""
    rid, desc, regex, ent, grp = rule
    body_start = len(regex) - len(LEADING.sub("", regex))
    m = re.search(r"[A-Za-z0-9_\-]{3,}", regex[body_start:])
    cut = body_start + (m.start() + 1 if m else 0)
    parts = f"{regex[:cut]!r} {regex[cut:]!r}" if 0 < cut < len(regex) else repr(regex)
    return f"({rid!r}, {desc!r}, {parts}, {ent!r}, {grp!r})"


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show = "--show-skipped" in sys.argv
    if args:
        text = Path(args[0]).read_text(encoding="utf-8")
    else:
        text = urllib.request.urlopen(SOURCE, timeout=30).read().decode("utf-8")
    data = tomllib.loads(text)
    kept, skipped = [], []
    for rule in data.get("rules", []):
        rid, regex = rule.get("id", ""), rule.get("regex", "")
        if not regex or "generic" in rid:
            skipped.append((rid, "generic", regex)); continue
        if not has_fixed_prefix(regex):
            skipped.append((rid, "no fixed prefix", regex)); continue
        py = to_python(regex)
        try:
            re.compile(py)
        except re.error as exc:
            skipped.append((rid, f"does not compile: {exc}", regex)); continue
        kept.append((rid, rule.get("description", rid), py, rule.get("entropy"), rule.get("secretGroup")))
    body = "\n".join("    " + literal(r) + "," for r in kept)
    OUT.write_text(f'''"""Secret formats imported from the gitleaks rule set. Generated file, do not edit.

Source: {SOURCE}
Fetched: {time.strftime("%Y-%m-%d")}
License: MIT, see THIRD_PARTY_LICENSES.md. Only rules with a fixed prefix are kept.
Regenerate with: python3 tools/sync_gitleaks.py
"""

# (id, description, regex, minimum entropy or None, secret capture group or None)
RULES = [
{body}
]
''', encoding="utf-8")
    print(f"kept {len(kept)} rules, skipped {len(skipped)} -> {OUT}")
    for rid, why, regex in skipped:
        if "compile" in why or show:
            print(f"  {rid:<34} {why:<20} {regex[:70]}")


if __name__ == "__main__":
    main()
