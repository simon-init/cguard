"""Rules, profiles and the user's configuration file.

Every rule has a mode: deny, ask or off. A profile is a set of default modes.
The user's file at ~/.claude/secret-guard.json holds the chosen profile, any
rule overrides, and the allowlists. The hook reads it on every call, so a change
applies to the next tool use without a restart.
"""
import json
import os
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("SECRET_GUARD_CONFIG") or os.path.expanduser("~/.claude/secret-guard.json"))
AUDIT_PATH = Path(os.environ.get("SECRET_GUARD_AUDIT") or os.path.expanduser("~/.claude/secret-guard.log"))
PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)

MODES = ("deny", "ask", "off")

# id, group, title, short description, long description
RULES = [
    ("secrets.files", "Secrets", "Files that hold secret material",
     "Refuse to read, edit, grep or shell-touch a file whose content looks like a key or credential.",
     "The path-based deny list in settings.json catches known names such as .env and the SSH folder. "
     "This rule catches the rest by content. Before a tool touches a file, the first 4 KB are read by "
     "the hook, never by the model. If they hold a private key block, a cloud or API key with a known "
     "prefix, a connection string with a password, or a KEY=value line whose value is long and random, "
     "the call is refused. Placeholders like your_api_key_here pass.\n\n"
     "Blocked: Read, Edit, Write, Grep on the file, and any shell command whose arguments name it.\n\n"
     "Way forward given to Claude: open the file yourself, or move the secret out of it, or allow the "
     "exact path with:  secret-guard allow paths <path>"),
    ("secrets.write", "Secrets", "Writing key material",
     "Refuse to write a private key block into any file.",
     "A private key that Claude writes to disk is a private key that was in the transcript first. "
     "Edit and Write calls whose content contains a private key header are refused. Keys are generated "
     "by tools such as ssh-keygen and never pass through the assistant."),
    ("secrets.env", "Secrets", "Environment variables that hold secrets",
     "Refuse env, printenv and echo of a variable whose name says it is a secret.",
     "Environment variables are where API keys actually live. Printing them puts the value into the "
     "transcript, and the transcript is context, which leaves the machine with every request.\n\n"
     "Blocked: env or printenv with no arguments, printenv NAME where NAME looks secret, echo or printf "
     "of $NAME where NAME contains SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or "
     "CREDENTIAL, and reads of /proc/*/environ. echo $HOME and echo $PATH pass."),

    ("commit.secrets", "Commits", "Secrets in a commit",
     "Scan what git add or git commit is about to record and refuse it if a secret is in it.",
     "On git add, the files being added are scanned. On git commit, the staged diff is scanned, or the "
     "working-tree diff when -a is used. The same detectors as secrets.files apply to the added lines.\n\n"
     "Way forward: remove the secret from the file, put it in an ignored .env or in the deployment "
     "platform, then commit again. A file that is legitimately committed with a token-shaped value, such "
     "as a test fixture, is allowed with:  secret-guard allow commit_paths <path>"),
    ("commit.binaries", "Commits", "Documents and large files in a commit",
     "Refuse git add of PDFs, office documents, archives, databases, and anything over the size limit.",
     "Real documents end up in repositories by accident: a browser download folder still set to the "
     "project, a test file dropped in the wrong place. Once pushed they are in history on every clone. "
     "This rule refuses git add of files whose extension is on the binary list, or whose size is above "
     "the limit (default 5 MB), unless the path is on the commit allowlist.\n\n"
     "Way forward: move the file out of the repository, or allow the exact path with:  "
     "secret-guard allow commit_paths <path>.  The list and the limit live in the configuration file."),
    ("commit.add_all", "Commits", "git add -A and git add .",
     "Refuse blanket adds. Files are added by name.",
     "git add -A, git add --all, git add . and git add * sweep in everything in the working tree, "
     "including files the user put there for other reasons. Adding named paths forces a look at what is "
     "going in. This is the rule that would have stopped the classic accident of committing a stray "
     "download.\n\nWay forward given to Claude: run git status, then git add <each path>."),
    ("commit.no_verify", "Commits", "Skipping commit hooks",
     "Refuse git commit or git push with --no-verify.",
     "--no-verify exists to skip pre-commit and pre-push checks, which are usually exactly the checks "
     "that stop secrets and broken code from leaving the machine. If a hook is wrong, fix the hook."),
    ("commit.force_push", "Commits", "Force push",
     "Ask before git push --force, -f or --force-with-lease.",
     "A force push rewrites history that other clones and other people may hold. Sometimes it is the "
     "right thing, for example after removing a secret from history. It is never the routine thing, so "
     "a person confirms it each time."),

    ("commands.fatal", "Commands", "Commands that destroy a machine",
     "Refuse rm -rf on /, ~ or ., mkfs, dd onto a disk, fork bombs.",
     "These have no legitimate use inside an assistant session and no undo. rm -rf / or ~ or . deletes "
     "everything the shell can reach. mkfs formats a disk. dd of=/dev/... overwrites one. If one of them "
     "is ever needed, a person types it in a terminal they are looking at."),
    ("commands.destructive", "Commands", "Commands that lose work",
     "Ask before git reset --hard, git clean -f, chmod -R 777, docker prune, DROP TABLE and similar.",
     "Each of these throws something away that git or a backup may not have: uncommitted changes, "
     "untracked files, file permissions, Docker images and volumes, a database table. They are "
     "legitimate often enough that refusing them outright would be an obstacle, so they ask, and the "
     "question shows exactly what will be lost.\n\n"
     "The list: git reset --hard, git clean with -f, git checkout -- . and git restore . (discard all "
     "changes), git branch -D, chmod -R 777, chown -R, docker system prune, docker volume prune, "
     "docker run with --privileged or the Docker socket mounted, DROP TABLE, DROP DATABASE, TRUNCATE, "
     "kill -9 -1."),
    ("commands.sudo", "Commands", "sudo",
     "Ask before any command run as root.",
     "sudo removes the last safety net under everything else on this list. The ask shows the full "
     "command so a person can read it before it runs with full rights."),

    ("exfil.pipe_to_shell", "Data leaving", "Download piped into a shell",
     "Refuse curl or wget piped into sh, bash, python or similar.",
     "curl URL | sh downloads a script and runs it without anyone reading it. It is how many tools tell "
     "you to install them, and it is also the most common way a developer machine is compromised.\n\n"
     "Way forward given to Claude: download the script to a file, show the user where it is, let them "
     "read it, then run it from the file."),
    ("exfil.upload", "Data leaving", "Sending files to another host",
     "Ask before curl uploads, scp, rsync, sftp or nc to a host that is not on the allowlist.",
     "A file leaving the machine should be a decision, not a side effect. curl with -d @file, -F, -T or "
     "--upload-file, and scp, rsync, sftp, nc and socat to a remote host, ask first. Hosts on the "
     "allowlist pass. Add your own server with:  secret-guard allow hosts <host>.  localhost is always "
     "allowed."),

    ("self.protect", "The guard itself", "Protect the guard and the credentials",
     "Refuse edits to the plugin, its configuration file, settings.json and the credentials file.",
     "A prompt injection that says 'first disable the security hook' should have nowhere to go. Claude "
     "may read the configuration but may not edit it with Edit, Write or a shell redirect. Changes go "
     "through the command line tool, which Claude can run when you ask it to:  secret-guard set <rule> "
     "<mode>,  secret-guard allow <list> <value>,  secret-guard profile <name>."),

    ("paths.boundary", "Boundary", "Stay inside the project",
     "Ask before touching a file outside the working directory and the allowed folders.",
     "A session opened in one project has no business in your browser profile, another client's folder "
     "or your documents. Reads, edits and shell commands that name an existing path outside the working "
     "directory ask first. Always allowed: the working directory, the Claude configuration folder, /tmp "
     "and the paths on the allowlist.\n\nWay forward given to Claude: open a Claude session in that "
     "folder instead, or allow the folder with:  secret-guard allow paths <folder>.  Off by default on "
     "the personal profile, ask on the shared profile."),
    ("packages.install", "Boundary", "Installing packages",
     "Ask before pip install, npm install, npx, cargo install, brew, pacman, apt and similar.",
     "Every install pulls code from the internet onto the machine, and an assistant can do it dozens of "
     "times an hour without anyone noticing what arrived. The ask shows the package names. Off by "
     "default on the personal profile, ask on the shared profile."),

    ("session.check", "Session", "Hygiene check at session start",
     "At session start, warn once if .env is not ignored or a tracked file looks like it holds a secret.",
     "Runs once per session, in the repository the session opened in. It checks that .env appears in "
     ".gitignore, and scans up to 500 tracked files for secret material. If something is found, one "
     "warning line is added to the session's context. Modes deny and ask both mean on. Off by default "
     "because it costs a few tokens per session."),
]

GROUPS = []
for _r in RULES:
    if _r[1] not in GROUPS:
        GROUPS.append(_r[1])

PROFILES = {
    "personal": {
        "secrets.files": "deny", "secrets.write": "deny", "secrets.env": "deny",
        "commit.secrets": "deny", "commit.binaries": "deny", "commit.add_all": "deny",
        "commit.no_verify": "deny", "commit.force_push": "ask",
        "commands.fatal": "deny", "commands.destructive": "ask", "commands.sudo": "ask",
        "exfil.pipe_to_shell": "deny", "exfil.upload": "ask",
        "self.protect": "deny",
        "paths.boundary": "off", "packages.install": "off",
        "session.check": "off",
    },
    "shared": {
        "secrets.files": "deny", "secrets.write": "deny", "secrets.env": "deny",
        "commit.secrets": "deny", "commit.binaries": "deny", "commit.add_all": "deny",
        "commit.no_verify": "deny", "commit.force_push": "ask",
        "commands.fatal": "deny", "commands.destructive": "ask", "commands.sudo": "ask",
        "exfil.pipe_to_shell": "deny", "exfil.upload": "ask",
        "self.protect": "deny",
        "paths.boundary": "ask", "packages.install": "ask",
        "session.check": "ask",
    },
}

DEFAULT_LISTS = {
    "paths": [],            # folders or files allowed for secrets.files and paths.boundary
    "hosts": [],            # hosts allowed for exfil.upload, besides localhost
    "commit_paths": [],     # repository-relative paths allowed past commit.secrets and commit.binaries
    "binary_extensions": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
                          ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".sqlite", ".sqlite3", ".db",
                          ".dmg", ".iso", ".pkl", ".parquet", ".safetensors", ".gguf", ".bin"],
    "max_file_mb": 5,
}


def rule_ids():
    return [r[0] for r in RULES]


def rule(rule_id):
    for r in RULES:
        if r[0] == rule_id:
            return {"id": r[0], "group": r[1], "title": r[2], "short": r[3], "long": r[4]}
    raise KeyError(rule_id)


def default_config(profile="personal"):
    return {"profile": profile, "rules": dict(PROFILES[profile]), "lists": json.loads(json.dumps(DEFAULT_LISTS)),
            "audit": {"decisions": True, "commands": False}}


def load():
    """The effective configuration: profile defaults, then the user's overrides."""
    user = {}
    if CONFIG_PATH.exists():
        try:
            user = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            user = {}
    profile = user.get("profile") if user.get("profile") in PROFILES else "personal"
    cfg = default_config(profile)
    for rid, mode in (user.get("rules") or {}).items():
        if rid in cfg["rules"] and mode in MODES:
            cfg["rules"][rid] = mode
    for name, value in (user.get("lists") or {}).items():
        if name in cfg["lists"]:
            cfg["lists"][name] = value
    for name, value in (user.get("audit") or {}).items():
        if name in cfg["audit"]:
            cfg["audit"][name] = bool(value)
    return cfg


def save(cfg):
    """Write only what differs from the profile, so the file stays readable."""
    base = default_config(cfg["profile"])
    out = {"profile": cfg["profile"],
           "rules": {k: v for k, v in cfg["rules"].items() if base["rules"].get(k) != v},
           "lists": {k: v for k, v in cfg["lists"].items() if base["lists"].get(k) != v},
           "audit": {k: v for k, v in cfg["audit"].items() if base["audit"].get(k) != v}}
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return CONFIG_PATH


def set_rule(cfg, rule_id, mode):
    if rule_id not in cfg["rules"]:
        raise KeyError(f"no rule named {rule_id}; run: secret-guard rules")
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    cfg["rules"][rule_id] = mode


def add_to_list(cfg, name, value):
    if name not in ("paths", "hosts", "commit_paths", "binary_extensions"):
        raise KeyError("list must be one of paths, hosts, commit_paths, binary_extensions")
    if name == "paths":
        value = os.path.abspath(os.path.expanduser(value))
    if value not in cfg["lists"][name]:
        cfg["lists"][name].append(value)


def remove_from_list(cfg, name, value):
    if name == "paths":
        value = os.path.abspath(os.path.expanduser(value))
    if value in cfg["lists"].get(name, []):
        cfg["lists"][name].remove(value)
