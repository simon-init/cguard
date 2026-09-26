"""Rules, profiles and the user's configuration file.

Every rule has a mode: deny, ask or off. A profile is a set of default modes.
The user's file at ~/.claude/cguard.json holds the chosen profile, any rule
overrides, and the allowlists. The hook reads it on every call, so a change
applies to the next tool use without a restart.
"""
import json
import os
from pathlib import Path

from . import patterns

CONFIG_PATH = Path(os.environ.get("CGUARD_CONFIG") or os.path.expanduser("~/.claude/cguard.json"))
AUDIT_PATH = Path(os.environ.get("CGUARD_AUDIT") or os.path.expanduser("~/.claude/cguard.log"))
PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)

MODES = ("deny", "ask", "off")
FORMATS = len(patterns.PREFIXED)

ABOUT = f"""cguard is one hook that Claude Code runs before every Read, Edit, Write, Grep and
shell command. The hook sees the tool call, decides, and prints one of three answers:
nothing, which lets the call through; ask, which makes Claude Code show you the call and
wait for a yes; or deny, which refuses it. The model sees only the decision and its
reason, never the content the hook looked at.

Every refusal has the same shape: what was blocked, why in one line, how to do it
yourself, and how to allow it. Claude relays that to you. You are never left with a wall.

Modes. Each rule is deny, ask or off. A deny refuses the call, and Claude relays the reason to you. An ask opens Claude Code's own permission dialog, the one with Yes, No and "tell Claude what to do differently", with cguard's reason shown in it, so you choose with the arrow keys and Enter. That dialog appears even when you run with permission prompts switched off, because the hook runs regardless of that setting. A refusal costs about one short message. An ask costs nothing until you answer. Nothing is added to the turns where the guard did not fire, which is what keeps it cheap. Two profiles
set the defaults: standard, where Claude moves freely between folders, and contained, where
it stays inside the project and asks before installing anything.

Detection. Secrets are found by content, not by file name. The hook reads at most the
first 4 KB of a file and looks for {FORMATS} known key formats, plus NAME=value lines where
the name says secret and the value looks random. That list covers the common cases and
cannot cover every one: a secret past the
first 4 KB, a format not on the list, or a secret that reads as ordinary words all pass.
The deny list in Claude Code's settings, which blocks known file names, is the layer
below this one, and a real sandbox is the layer below that.

Everything the hook decides is written to a local log, with secrets masked, so you can
always ask what happened and why: cguard audit, cguard why."""

# id, group, title, short, long
RULES = [
    ("secrets.files", "Secrets", "Files that hold secret material",
     "Refuse to read, edit, grep or shell-touch a file whose content looks like a key or credential.",
     f"How it works. Before a tool touches a file, the hook opens that file itself and reads its "
     f"first 4 KB. It looks for two things.\n\n"
     f"First, {FORMATS} known formats with a fixed shape: private key blocks, keys for AWS, Anthropic, "
     f"OpenAI, GitHub, GitLab, Hugging Face, Replicate, npm, Stripe, Square, SendGrid, Slack and "
     f"Langfuse, Google service account files, kubeconfig keys, connection strings and URLs that "
     f"carry a password, bearer tokens and JSON web tokens.\n\n"
     f"Second, any line of the form NAME=value or NAME: value where NAME contains SECRET, TOKEN, "
     f"PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or CREDENTIAL, and the value is at least 12 "
     f"characters and looks random, measured as 3.0 bits of entropy or more. Placeholders such as "
     f"your_api_key_here, <fill in> or a run of the same character pass.\n\n"
     f"The file content is read by the hook, never by the model. Only the decision reaches Claude.\n\n"
     f"What it does not catch: a secret past the first 4 KB, a format that is not on the list, and a "
     f"secret that reads as ordinary words. It is a net for the common case. The deny list in Claude "
     f"Code's settings, which blocks known names such as .env and the SSH folder, stays in place "
     f"underneath it.\n\n"
     f"Way forward given to Claude: open the file yourself, or move the secret out of it, or allow "
     f"the exact path with:  cguard allow paths <path>"),
    ("secrets.write", "Secrets", "Writing key material",
     "Refuse to write a private key block into any file.",
     "How it works. Edit and Write calls carry their new content in the tool call. The hook "
     "searches that content for the headers that begin a private key: the BEGIN ... PRIVATE KEY "
     "block, PuTTY key files, and age secret keys. If one is there, the call is refused.\n\n"
     "Why it exists. A key that Claude writes to disk was in the transcript first, and the "
     "transcript leaves the machine with every request. Keys are generated by tools such as "
     "ssh-keygen and never typed by an assistant.\n\n"
     "What it does not catch: key material without a recognisable header, and a key written by a "
     "program Claude ran rather than by Claude directly."),
    ("secrets.env", "Secrets", "Environment variables that hold secrets",
     "Refuse env, printenv and echo of a variable whose name says it is a secret.",
     "How it works. The hook reads the shell command as text and looks for four things: env or "
     "printenv with no arguments, which print every variable; printenv NAME where NAME contains "
     "SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or CREDENTIAL; echo or printf of "
     "$NAME with such a name; and reads of /proc/*/environ, which is another process's environment. "
     "echo $HOME and printenv PATH pass.\n\n"
     "Why it exists. Environment variables are where API keys actually live. Printing one puts "
     "the value into the transcript, and the transcript is context, which leaves the machine with "
     "every request.\n\n"
     "What it does not catch: a variable with an innocent name, and a value read by a script "
     "rather than printed by the shell. If Claude needs to know whether a variable is set, it can "
     "test for that without printing the value."),

    ("commit.secrets", "Commits", "Secrets in a commit",
     "Scan what git add or git commit is about to record and refuse it if a secret is in it.",
     "How it works. On git add, the hook opens each file being added, or every file under a "
     "folder being added up to 500 files, and runs the same detectors as the secrets.files rule. "
     "On git commit, it asks git for the staged diff, or the working-tree diff when -a is used, "
     "and scans the added lines only. A hit refuses the command and names the file.\n\n"
     "Why it exists. A secret in a commit is a secret in every clone, forever, and removing it "
     "later means rewriting history on every machine that pulled it.\n\n"
     "What it does not catch: a secret that none of the detectors recognise, and anything staged "
     "and pushed outside a Claude session.\n\n"
     "Way forward: move the value into an ignored .env file or into the deployment platform, then "
     "commit again. A file that legitimately holds a token-shaped value, such as a test fixture, "
     "is allowed with:  cguard allow commit_paths <path>"),
    ("commit.binaries", "Commits", "Documents and large files in a commit",
     "Refuse git add of PDFs, office documents, archives, databases, and anything over the size limit.",
     "How it works. On git add, and on git commit for files already staged, the hook checks each "
     "new file's extension against the binary list, and its size against the limit, 5 MB by "
     "default. Both live in the configuration file. A path on the commit allowlist passes.\n\n"
     "Why it exists. Real documents end up in repositories by accident: a browser download folder "
     "still set to the project, a test file dropped in the wrong place. Once pushed, they are in "
     "history on every clone. This rule was written the day after exactly that happened.\n\n"
     "What it does not catch: a document with an extension that is not on the list, and a file "
     "under the size limit with a text extension.\n\n"
     "Way forward: move the file out of the repository, or allow the exact path with:  "
     "cguard allow commit_paths <path>"),
    ("commit.add_all", "Commits", "git add -A and git add .",
     "Refuse blanket adds. Files are added by name.",
     "How it works. The hook reads the git command and refuses git add when its arguments contain "
     "-A, --all, . or *. Adding named paths, or git add -u for tracked files only, passes.\n\n"
     "Why it exists. A blanket add sweeps in everything in the working tree, including files you "
     "put there for other reasons. Adding by name forces a look at what is going in, and it is "
     "the rule that would have stopped the classic accident of committing a stray download.\n\n"
     "Way forward given to Claude: run git status, then git add each intended path."),
    ("commit.no_verify", "Commits", "Skipping commit hooks",
     "Refuse git commit or git push with --no-verify.",
     "How it works. The hook refuses git commit and git push when their arguments contain "
     "--no-verify, or the short form -n on commit.\n\n"
     "Why it exists. That flag exists to skip pre-commit and pre-push hooks, and those hooks are "
     "usually exactly the checks that stop secrets and broken code from leaving the machine. If a "
     "hook is wrong, the hook gets fixed. If it must be skipped once, a person does it."),
    ("commit.force_push", "Commits", "Force push",
     "Ask before git push --force, -f or --force-with-lease.",
     "How it works. The hook asks for confirmation when a git push carries --force, -f, "
     "--force-with-lease, or a refspec that begins with +.\n\n"
     "Why it exists. A force push rewrites history that other clones and other people may hold. "
     "Sometimes it is the right thing, for example after removing a secret from history. It is "
     "never the routine thing, so a person confirms it each time and sees the full command."),

    ("commands.fatal", "Commands", "Commands that destroy a machine",
     "Refuse rm -rf on /, ~ or ., mkfs, dd onto a disk, fork bombs.",
     "How it works. The hook splits the shell line into commands and looks at each. rm with a "
     "recursive flag whose target is /, /*, ~, $HOME, ., .., * or a top-level system folder is "
     "refused. So is mkfs in any form, dd with a disk device as its output, a redirect onto a disk "
     "device, shred on a device, chmod 777 on /, and the fork bomb.\n\n"
     "Why it exists. None of these has a legitimate use inside an assistant session, and none has "
     "an undo. If one is ever needed, a person types it in a terminal they are looking at.\n\n"
     "What it does not catch: the same effect reached through a script, a variable that expands "
     "to one of those targets, or a command the hook does not know. This is a list, not a proof."),
    ("commands.destructive", "Commands", "Commands that lose work",
     "Ask before git reset --hard, git clean -f, chmod -R 777, docker prune, DROP TABLE and similar.",
     "How it works. The hook matches the shell line against a list of commands that throw "
     "something away, and asks for confirmation with the command shown in full.\n\n"
     "The list: git reset --hard, git clean with -f, git checkout -- . and git restore . which "
     "discard all changes, git branch -D, chmod -R 777, chown -R, docker system prune, docker "
     "volume prune, docker image prune, docker run with --privileged or with the Docker socket "
     "mounted, DROP TABLE, DROP DATABASE, DROP SCHEMA, TRUNCATE, and kill -9 -1.\n\n"
     "Why it asks rather than refuses. Each of these is legitimate often enough that a refusal "
     "would be an obstacle. What they share is that git or a backup may not have what they "
     "delete: uncommitted changes, untracked files, permissions, images and volumes, a table. A "
     "yes from a person who has read the command is the right price."),
    ("commands.sudo", "Commands", "sudo",
     "Ask before any command run as root.",
     "How it works. The hook asks for confirmation when a command, or any command in a chain, "
     "begins with sudo, doas or su.\n\n"
     "Why it exists. Root removes the last safety net under everything else on this list. The ask "
     "shows the full command so a person reads it before it runs with full rights. On a machine "
     "where Claude never needs root, set this to deny."),

    ("exfil.pipe_to_shell", "Data leaving", "Download piped into a shell",
     "Refuse curl or wget piped into sh, bash, python or similar.",
     "How it works. The hook refuses a shell line where curl or wget is piped, directly or "
     "through sudo, into sh, bash, zsh, fish, dash, python, perl, node or ruby.\n\n"
     "Why it exists. curl URL | sh downloads a script and runs it before anyone has read it. It "
     "is how many tools tell you to install them, and it is also the most common way a developer "
     "machine is compromised.\n\n"
     "Way forward given to Claude: download the script to a file, tell the user where it is so "
     "they can read it, then run it from the file."),
    ("exfil.upload", "Data leaving", "Sending files to another host",
     "Ask before curl uploads, scp, rsync, sftp or nc to a host that is not on the allowlist.",
     "How it works. The hook looks for three shapes: curl with a data or upload flag such as -d, "
     "--data-binary, -F, -T or --upload-file; scp, rsync or sftp with a host:path argument; and "
     "nc, ncat, netcat or socat with a host. It reads the host out of the command and asks unless "
     "that host is localhost or on the allowlist.\n\n"
     "Why it exists. A file leaving the machine should be a decision, not a side effect of a "
     "command that looked routine.\n\n"
     "What it does not catch: an upload done by a program Claude wrote, a host hidden in a "
     "variable, and tools not on the list.\n\n"
     "Way forward: add your own machines once with:  cguard allow hosts <host>"),

    ("self.protect", "The guard itself", "Protect the guard and the credentials",
     "Refuse edits to the plugin, its configuration file, Claude Code's own settings and the credentials file.",
     "How it works. The hook refuses Edit and Write on the plugin's own files, on its "
     "configuration file, on Claude Code's settings file and on the credentials file, and it "
     "refuses shell commands that both name one of those paths and contain a way of writing to "
     "it: a redirect, sed -i, tee, rm, mv, cp, truncate, chmod, or an interpreter. Reading them "
     "is allowed. The cguard command line is allowed, because that is the intended way to change "
     "the configuration.\n\n"
     "Why it exists. A prompt injection that says 'first disable the security hook' should have "
     "nowhere to go. Changes go through the tool, which Claude runs only when you ask:  cguard "
     "set <rule> <mode>,  cguard allow <list> <value>,  cguard profile <name>."),

    ("paths.boundary", "Boundary", "Stay inside the project",
     "Ask before touching a file outside the working directory and the allowed folders.",
     "How it works. For Read, Edit, Write and Grep the hook checks the target path. For a shell "
     "command it checks every argument that names an existing file or folder. A path outside the "
     "working directory asks for confirmation, unless it is under the Claude configuration "
     "folder, /tmp, or a folder on the allowlist.\n\n"
     "Why it exists. A session opened in one project has no business in your browser profile, "
     "another client's folder or your documents. On a machine that holds only your own work this "
     "is more obstacle than protection, which is why the standard profile leaves it off and the "
     "contained profile sets it to ask.\n\n"
     "Way forward given to Claude: open a Claude session in that folder instead, or allow the "
     "folder with:  cguard allow paths <folder>"),
    ("packages.install", "Boundary", "Installing packages",
     "Ask before pip install, npm install, npx, cargo install, brew, pacman, apt and similar.",
     "How it works. The hook matches the shell line against the install commands of the common "
     "package managers: pip, uv, npm, pnpm, yarn, bun, npx, cargo, go, brew, pacman, paru, yay, "
     "apt and gem, and asks for confirmation with the command shown.\n\n"
     "Why it exists. Every install pulls code from the internet onto the machine, and an "
     "assistant can do it dozens of times an hour without anyone noticing what arrived. Off by "
     "default on the standard profile, ask on the contained profile."),

    ("session.check", "Session", "Hygiene check at session start",
     "At session start, warn once if .env is not ignored or a tracked file looks like it holds a secret.",
     "How it works. Once per session, in the repository the session opened in, the hook checks "
     "that .env appears in .gitignore and scans up to 500 tracked files with the same detectors as "
     "the secrets.files rule. If something is found, one warning line is added to the session's "
     "context and Claude tells you once.\n\n"
     "Modes deny and ask both mean on. Off by default because it costs a few tokens per session."),
]

GROUPS = []
for _r in RULES:
    if _r[1] not in GROUPS:
        GROUPS.append(_r[1])

PROFILE_INFO = {
    "standard": ("Guards on, free to move between folders",
                 "Secrets, commits and the machine are guarded. Claude can move between the folders on this "
                 "machine and install packages without asking. Choose this when the folders here are all part "
                 "of the work and you want the least friction."),
    "contained": ("Guards on, and Claude stays inside the project",
                  "Everything in standard, plus containment. Claude stays inside the project it was opened in "
                  "and asks before touching anything outside it. It asks before installing anything. And the "
                  "session check warns once when a repository is not keeping its secrets out of git. Choose "
                  "this when the machine holds folders that are not part of the work, or when other people rely "
                  "on you keeping things apart."),
}
OLD_PROFILE_NAMES = {"personal": "standard", "own-work": "standard", "shared": "contained", "client-data": "contained"}

PROFILES = {
    "standard": {
        "secrets.files": "deny", "secrets.write": "deny", "secrets.env": "deny",
        "commit.secrets": "deny", "commit.binaries": "deny", "commit.add_all": "deny",
        "commit.no_verify": "deny", "commit.force_push": "ask",
        "commands.fatal": "deny", "commands.destructive": "ask", "commands.sudo": "ask",
        "exfil.pipe_to_shell": "deny", "exfil.upload": "ask",
        "self.protect": "deny",
        "paths.boundary": "off", "packages.install": "off",
        "session.check": "off",
    },
    "contained": {
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


def default_config(profile="standard"):
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
    profile = OLD_PROFILE_NAMES.get(user.get("profile"), user.get("profile"))
    if profile not in PROFILES:
        profile = "standard"
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
        raise KeyError(f"no rule named {rule_id}; run: cguard rules")
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


def profile_differences(name):
    """Rules whose mode in `name` differs from the other profile: [(rule_id, mine, theirs)]."""
    other = next(n for n in PROFILES if n != name)
    return [(rid, PROFILES[name][rid], PROFILES[other][rid]) for rid in rule_ids() if PROFILES[name][rid] != PROFILES[other][rid]]
