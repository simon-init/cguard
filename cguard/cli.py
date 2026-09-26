#!/usr/bin/env python3
"""The command line: read and change the configuration, read the audit log, dry-run a
command. Claude can run every subcommand except `config`, which is the interactive screen.
"""
import json
import os
import sys
import textwrap

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cguard import __version__, audit, config, guards, patterns  # noqa: E402

USAGE = """cguard: guards for a Claude Code session

  cguard show                       current profile, rule modes and allowlists
  cguard rules                      every rule with a one-line description
  cguard explain <rule>             the full description of one rule
  cguard set <rule> <deny|ask|off>  change one rule
  cguard allow <list> <value>       add to an allowlist: paths, hosts, commit_paths, binary_extensions
  cguard remove <list> <value>      remove from an allowlist
  cguard profile <personal|shared>  switch profile (resets rule modes to that profile's defaults)
  cguard audit [n]                  the last n decisions (default 20)
  cguard why                        the most recent refusal, explained
  cguard check '<shell command>'    what the guard would do with a command, without running it
  cguard check-file <path>          whether a file counts as secret material
  cguard config                     the interactive settings screen (needs a real terminal)
  cguard version
"""


def cmd_show(cfg):
    print(f"profile: {cfg['profile']}    config: {config.CONFIG_PATH}    audit: {config.AUDIT_PATH}")
    print()
    for group in config.GROUPS:
        print(group)
        for r in config.RULES:
            if r[1] == group:
                print(f"  {cfg['rules'][r[0]]:<5} {r[0]:<22} {r[2]}")
    print()
    for name in ("paths", "hosts", "commit_paths"):
        values = cfg["lists"][name]
        print(f"{name:<14} {', '.join(values) if values else '(none)'}")
    print(f"{'binaries':<14} {', '.join(cfg['lists']['binary_extensions'])}")
    print(f"{'max_file_mb':<14} {cfg['lists']['max_file_mb']}")
    print(f"{'audit':<14} decisions={'on' if cfg['audit']['decisions'] else 'off'} commands={'on' if cfg['audit']['commands'] else 'off'}")


def cmd_rules(cfg):
    for r in config.RULES:
        print(f"{cfg['rules'][r[0]]:<5} {r[0]:<22} {r[3]}")


def cmd_explain(cfg, rule_id):
    r = config.rule(rule_id)
    print(f"{r['id']}  ({r['group']})  mode: {cfg['rules'][r['id']]}\n{r['title']}\n")
    for para in r["long"].split("\n\n"):
        print(textwrap.fill(para, width=88))
        print()


def cmd_audit(n):
    entries = audit.tail(n)
    if not entries:
        print("no entries")
        return
    for e in entries:
        if e.get("kind") == "decision":
            print(f"{e['ts']}  {e['mode']:<5} {e['rule']:<22} {e.get('what', '')[:100]}")
        elif e.get("kind") == "command":
            print(f"{e['ts']}  cmd   {e.get('command', '')[:110]}")
        else:
            print(f"{e['ts']}  {e.get('kind')}  {e.get('error', '')[:100]}")


def cmd_why():
    for e in reversed(audit.tail(200)):
        if e.get("kind") == "decision":
            print(f"{e['ts']}: {e['mode']} by {e['rule']}\n  {e.get('what', '')}\n  in {e.get('cwd', '')}")
            print()
            cmd_explain(config.load(), e["rule"])
            return
    print("no refusal recorded yet")


def cmd_check(cfg, command):
    data = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": os.getcwd()}
    d = guards.evaluate(data, cfg)
    if not d:
        print("allowed")
        return 0
    print(d.reason())
    return 1


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0
    cmd, args = argv[0], argv[1:]
    cfg = config.load()
    try:
        if cmd == "show":
            cmd_show(cfg)
        elif cmd == "rules":
            cmd_rules(cfg)
        elif cmd == "explain" and len(args) == 1:
            cmd_explain(cfg, args[0])
        elif cmd == "set" and len(args) == 2:
            config.set_rule(cfg, args[0], args[1])
            print(f"{args[0]} = {args[1]}  (saved to {config.save(cfg)})")
        elif cmd == "allow" and len(args) == 2:
            config.add_to_list(cfg, args[0], args[1])
            print(f"added to {args[0]}: {args[1]}  (saved to {config.save(cfg)})")
        elif cmd == "remove" and len(args) == 2:
            config.remove_from_list(cfg, args[0], args[1])
            print(f"removed from {args[0]}: {args[1]}  (saved to {config.save(cfg)})")
        elif cmd == "profile" and len(args) == 1:
            if args[0] not in config.PROFILES:
                raise ValueError(f"profile must be one of {', '.join(config.PROFILES)}")
            new = config.default_config(args[0])
            new["lists"], new["audit"] = cfg["lists"], cfg["audit"]
            print(f"profile = {args[0]}  (saved to {config.save(new)})")
        elif cmd == "audit":
            cmd_audit(int(args[0]) if args else 20)
        elif cmd == "why":
            cmd_why()
        elif cmd == "check" and args:
            return cmd_check(cfg, " ".join(args))
        elif cmd == "check-file" and len(args) == 1:
            label = patterns.classify_file(os.path.abspath(os.path.expanduser(args[0])))
            print(f"{args[0]}: {label or 'no secret material found in the first 4 KB'}")
            return 1 if label else 0
        elif cmd == "config":
            from cguard import tui
            tui.run()
        elif cmd == "version":
            print(__version__)
        else:
            print(USAGE)
            return 2
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
