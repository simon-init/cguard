"""The guided setup: run once after install, safe to run again.

Plain prompts, so it works in any terminal. Each step shows the current value and takes
Enter as "keep it". Writes the configuration file and, on request, the known secret paths.
"""
import os
import platform
import sys

from . import __version__, config, denylist

ACCENT, BOLD, DIM, OK, WARN, RESET = "\033[36m", "\033[1m", "\033[2m", "\033[32m", "\033[33m", "\033[0m"
TAGLINE = "You decide what Claude can reach."


def _color():
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def c(code, text):
    return f"{code}{text}{RESET}" if _color() else text


def ask(prompt, default=""):
    shown = f" [{default}]" if default else ""
    try:
        answer = input(f"  {prompt}{shown}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(1)
    return answer or default


def header(step, title):
    print()
    print(c(ACCENT + BOLD, f"{step}  {title}"))
    print(c(DIM, "  " + "─" * 60))


def os_name():
    return {"Linux": "Linux", "Darwin": "macOS", "Windows": "Windows"}.get(platform.system(), platform.system())


def rules_for_this_os():
    system = platform.system()
    n = 0
    for r in denylist.RULES:
        if "~/Library/" in r or "/Library/" in r:
            n += system == "Darwin"
        elif "AppData" in r:
            n += system == "Windows"
        else:
            n += 1
    return n


def run():
    cfg = config.load()
    first = not config.CONFIG_PATH.exists()
    print()
    print(c(ACCENT + BOLD, f"  cguard {__version__}") + c(DIM, "   guards for a Claude Code session"))
    print(c(BOLD, f"  {TAGLINE}"))
    print()
    print("  A hook runs before every file and shell tool. It refuses or asks before Claude touches a")
    print("  secret, commits a stray file or runs a command that cannot be undone. The rules are yours.")
    print(c(DIM, "  Enter keeps the value shown in brackets. Ctrl+C leaves without saving."))

    # 1. profile
    header("1", "Profile")
    names = list(config.PROFILES)
    for i, name in enumerate(names, 1):
        title, _ = config.PROFILE_INFO[name]
        mark = c(OK, "●") if name == cfg["profile"] else c(DIM, "○")
        print(f"  {mark} {i}  {c(BOLD, f'{name:<12}')} {c(DIM, title)}")
    diffs = ", ".join(f"{rid} {mine}" for rid, mine, _ in config.profile_differences("contained"))
    print(c(DIM, f"     contained adds: {diffs}"))
    choice = ask("Profile, 1 or 2", str(names.index(cfg["profile"]) + 1))
    if choice in ("1", "2") and names[int(choice) - 1] != cfg["profile"]:
        fresh = config.default_config(names[int(choice) - 1])
        fresh["lists"], fresh["audit"] = cfg["lists"], cfg["audit"]
        cfg = fresh
    print(f"  profile: {c(BOLD, cfg['profile'])}")

    # 2. known secret paths
    header("2", "Known secret paths")
    present, missing = denylist.status()
    print(f"  {len(denylist.RULES)} rules for Claude Code's own permissions: SSH keys, env files, credentials,")
    print(f"  history, browsers, keychains, and the commands that print a secret.")
    print(f"  This is {os_name()}: {rules_for_this_os()} of them apply here, the rest never match and cost nothing.")
    print(f"  In {denylist.SETTINGS_PATH}: {c(BOLD, str(len(present)))} present, {c(BOLD, str(len(missing)))} missing.")
    if missing:
        if ask(f"Add the {len(missing)} missing rules? y/n", "y").lower().startswith("y"):
            added = denylist.install()
            print(f"  {c(OK, 'added')} {added}. Claude Code loads them at its next start.")
        else:
            print(c(DIM, "  skipped. Later: cguard denylist install"))
    else:
        print(c(OK, "  all present."))

    # 3. trusted hosts
    header("3", "Trusted hosts")
    print("  The upload guard asks before Claude sends a file to a host it does not know, with scp,")
    print("  rsync or a curl upload. Machines you send files to on purpose go here, so those commands")
    print("  never ask. Your own server, for example. localhost is always trusted.")
    current = cfg["lists"]["hosts"]
    print(f"  now: {', '.join(current) if current else c(DIM, 'none')}")
    answer = ask("Hosts to add, comma separated, or Enter for none", "")
    for host in [h.strip() for h in answer.split(",") if h.strip()]:
        config.add_to_list(cfg, "hosts", host)
    if answer:
        print(f"  trusted: {', '.join(cfg['lists']['hosts'])}")

    # 4. commands
    header("4", "Five commands worth knowing")
    for cmd, what in (("cguard config", "the settings screen, every rule with its description"),
                      ("cguard why", "the last refusal, explained, with the way forward"),
                      ("cguard audit", "the last decisions"),
                      ("cguard set <rule> <deny|ask|off>", "change one rule; Claude can run this when you ask"),
                      ("cguard allow <paths|hosts|commit_paths> <value>", "allow one path, host or file")):
        print(f"  {c(BOLD, f'{cmd:<50}')} {c(DIM, what)}")
    print(c(DIM, "  Inside a session: /cguard:config, /cguard:why, /cguard:audit"))

    # 5. save
    header("5", "Done")
    path = config.save(cfg)
    print(f"  configuration: {c(BOLD, str(path))}")
    print(f"  log:           {c(BOLD, str(config.AUDIT_PATH))}")
    print(f"  profile {c(BOLD, cfg['profile'])}, {sum(1 for m in cfg['rules'].values() if m == 'deny')} rules deny, "
          f"{sum(1 for m in cfg['rules'].values() if m == 'ask')} ask, {sum(1 for m in cfg['rules'].values() if m == 'off')} off.")
    print(f"  {c(OK, 'The guard is live from the next Claude session you start or resume.')}")
    if first:
        print(c(DIM, "  Run cguard setup again any time to change these."))
    print()
    return 0
