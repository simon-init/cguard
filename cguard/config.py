"""Rules, profiles and the user's configuration file.

Every rule has a mode: deny, ask or off. A profile is a set of default modes.
The user's file at ~/.claude/cguard.json holds the chosen profile, any rule
overrides, and the allowlists. The hook reads it on every call, so a change
applies to the next tool use without a restart.

Description texts use a light markup: a line starting with "## " is a header,
a line starting with "- " is a bullet, blank lines separate paragraphs.
"""
import json
import os
from pathlib import Path

from . import patterns

CONFIG_PATH = Path(os.environ.get("CGUARD_CONFIG") or os.path.expanduser("~/.claude/cguard.json"))
AUDIT_PATH = Path(os.environ.get("CGUARD_AUDIT") or os.path.expanduser("~/.claude/cguard.log"))
PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT") or Path(__file__).resolve().parent.parent)

MODES = ("deny", "ask", "off")
OWN_FORMATS = len(patterns.PREFIXED)
IMPORTED_FORMATS = len(patterns.GITLEAKS)
FORMATS = OWN_FORMATS + IMPORTED_FORMATS

ABOUT = f"""## What it is
One hook. Claude Code runs it before every Read, Edit, Write, Grep and shell command.
The hook looks at the call and answers in one of three ways.

- Nothing: the call goes through.
- Ask: Claude Code opens its permission dialog, Yes, No and "tell Claude what to do differently", with cguard's reason shown in it. It appears even when permission prompts are switched off.
- Deny: the call is refused, and Claude relays the reason to you.

The model sees only the decision and its reason, never the content the hook looked at.

## Every blocked action comes with a safe alternative
The same four lines every time: what was blocked, why in one line, how to do it yourself, and how to allow it. You are never left with a wall.

## Modes and profiles
Each rule is deny, ask or off.

- A refusal costs about one short message: its reason enters the context and Claude relays it.
- An ask costs nothing until you answer.
- Nothing is added to turns where the guard did not fire. That is what keeps it cheap.

Two profiles set the defaults. Standard: Claude moves freely between folders. Contained: Claude stays inside the project and asks before installing anything.

## How secrets are found
By content, not by file name. The hook reads the first 64 KB of a file, which is the whole file for almost every configuration or source file, and never more than 4 MB in one tool call.

- {FORMATS} known key formats with a fixed shape: cloud, API and payment keys, private key blocks, connection strings, tokens. {OWN_FORMATS} are cguard's own and {IMPORTED_FORMATS} are imported from the gitleaks rule set, MIT, fixed-prefix rules only.
- NAME=value lines where the name says secret and the value looks random.

## Setup
cguard setup walks through the profile, the known secret paths, your trusted hosts and the commands, once after install. It is safe to run again.

## What it cannot see
- A secret past the first 64 KB of a large file.
- A format that is not on the list.
- A secret that reads as ordinary words.
- Anything a program does after Claude starts it.

The deny list in Claude Code's own settings, which blocks known file names, is the layer below this one. cguard carries those rules too: see Known secret paths in this screen, or run cguard denylist install. A real sandbox is the layer below that.

## Where things are
- Configuration: {CONFIG_PATH}. Edited by this screen and by the cguard command. Delete it to return to the standard profile with nothing changed.
- Log: {AUDIT_PATH}. One line per decision: time, tool, rule, mode, what was blocked, with secrets masked. Local only.
- Installed copy: under the Claude plugins folder. Updated with claude plugin update cguard@cguard.

## Reading the log
- cguard audit, the last 20 decisions. cguard audit 100 for more.
- cguard why, the most recent refusal with its full explanation. cguard why 3 for the third most recent, cguard why list to pick from the last twenty.
- cguard show, the current profile, rule modes and allowlists.
- Inside a session: /cguard:audit, /cguard:why, /cguard:config."""

DENYLIST_TEXT = """## What it is
A list of file names and folders that Claude Code refuses to read, edit or touch from a shell, before any hook runs. It lives in Claude Code's own settings file under permissions. A plugin cannot write there by itself, so cguard carries the rules and installs them when you ask.

## What is on the list
- SSH keys and the SSH folder, on any path, and key files by extension: pem, key, p12, pfx, p8, jks, keystore, asc, gpg, age, ovpn, PuTTY.
- Environment files: .env, .env.local, .env.production and the like. Password databases, Terraform state, htpasswd.
- Cloud and tool credentials: AWS, Azure, Google Cloud, Hetzner, Kubernetes, GPG, Docker, netrc, git credentials, password stores, rclone, sops, Vault, Pulumi, Doppler, Infisical.
- Developer tool tokens: GitHub CLI, npm, yarn, PyPI, cargo, gem, composer, maven, gradle, NuGet, pgpass, my.cnf, Databricks, Vercel, Netlify, Fly, Railway, DigitalOcean, Cloudflare, ngrok, Teleport, 1Password CLI, Hugging Face, Codex, OpenAI and Gemini folders.
- Claude Code's own credentials file.
- History files: shell, Python, database, Node, Ruby, Redis, Mongo, less, PowerShell.
- Keychains and keyrings, browser profiles, password managers, messaging apps and mail on Linux, macOS and Windows. The Windows paths are best effort and untested.
- Commands whose job is to print a secret: gh auth token, the cloud access-token commands, password manager reads, kubectl get secret, heroku config, vercel env pull, doppler, railway, vault, gpg secret export, env and printenv.

## How it differs from the secrets rule
The secrets rule looks inside a file and needs to recognise what it finds. This list needs nothing: a matching name is refused outright, whatever is in the file. The two layers cover each other's gaps.

## Commands
- cguard denylist status
- cguard denylist show
- cguard denylist install
- cguard denylist remove, the undo

You run install and remove in a terminal. Claude cannot run them, which is the self-protect rule."""

PROFILE_INFO = {
    "standard": ("Guards on, free to move between folders",
                 "## What is on\nSecrets, commits and the machine are guarded.\n\n"
                 "## What is not\nClaude can move between the folders on this machine and install packages without asking.\n\n"
                 "## Choose this when\nThe folders here are all part of the work and you want the least friction."),
    "contained": ("Guards on, and Claude stays inside the project",
                  "## What is on\nEverything in standard, plus containment.\n\n"
                  "- Claude stays inside the project it was opened in and asks before touching anything outside it.\n"
                  "- It asks before installing anything.\n"
                  "- The session check warns once when a repository is not keeping its secrets out of git.\n\n"
                  "## Choose this when\nThe machine holds folders that are not part of the work, or when keeping things apart matters."),
}
OLD_PROFILE_NAMES = {"personal": "standard", "own-work": "standard", "shared": "contained", "client-data": "contained"}

# id, group, title, short, long
RULES = [
    ("secrets.files", "Secrets", "Files that hold secret material",
     "Refuse to read, edit, grep or shell-touch a file whose content looks like a key or credential.",
     f"## How it works\n"
     f"Before a tool touches a file, the hook opens that file itself and reads the first 64 KB, which is the whole file for almost every configuration or source file. Across one tool call it reads no more than 4 MB in total. It looks for two things.\n\n"
     f"- {FORMATS} known formats with a fixed shape: private key blocks, keys for the major clouds, AI providers, payment and messaging services, Google service account files, kubeconfig keys, connection strings and URLs that carry a password, bearer tokens and JSON web tokens. {OWN_FORMATS} are cguard's own, {IMPORTED_FORMATS} are imported from the gitleaks rule set (MIT), fixed-prefix rules only, refreshed with tools/sync_gitleaks.py.\n"
     f"- Any NAME=value or NAME: value line where NAME contains SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or CREDENTIAL, and the value is at least 12 characters of key-like text, looks random, and is not a name from the code around it.\n\n"
     f"Placeholders such as your_api_key_here, <fill in> or a run of the same character pass. The file content is read by the hook, never by the model.\n\n"
     f"## What it does not catch\n"
     f"- A secret past the first 64 KB of a large file.\n"
     f"- A format that is not on the list.\n"
     f"- A secret that reads as ordinary words.\n"
     f"- A bare random string with no name in front of it and no known prefix, such as a raw base64 value on its own.\n\n"
     f"The deny list in Claude Code's own configuration, which blocks known names such as .env and the SSH folder, stays in place underneath.\n\n"
     f"## Safe alternative\n"
     f"Open the file yourself, or move the secret out of it, or allow the exact path:\n"
     f"cguard allow paths <path>"),
    ("secrets.write", "Secrets", "Writing key material",
     "Refuse to write a private key block into any file.",
     "## How it works\n"
     "Edit and Write calls carry their new content. The hook searches it for the headers that begin a private key: the BEGIN ... PRIVATE KEY block, PuTTY key files, age secret keys. If one is there, the call is refused.\n\n"
     "## Why it exists\n"
     "A key that Claude writes to disk was in the transcript first, and the transcript leaves the machine with every request. Keys are generated by tools such as ssh-keygen, never typed by an assistant.\n\n"
     "## What it does not catch\n"
     "- Key material without a recognisable header.\n"
     "- A key written by a program Claude ran."),
    ("secrets.env", "Secrets", "Environment variables that hold secrets",
     "Refuse env, printenv and echo of a variable whose name says it is a secret.",
     "## How it works\n"
     "The hook reads the shell command as text and refuses four things.\n\n"
     "- env or printenv with no arguments, which print every variable.\n"
     "- printenv NAME where NAME contains SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE_KEY, ACCESS_KEY or CREDENTIAL.\n"
     "- echo or printf of $NAME with such a name.\n"
     "- Reads of /proc/*/environ, another process's environment.\n\n"
     "echo $HOME and printenv PATH pass.\n\n"
     "## Why it exists\n"
     "Environment variables are where API keys live. Printing one puts the value into the transcript, and the transcript leaves the machine with every request.\n\n"
     "## What it does not catch\n"
     "- A variable with an innocent name.\n"
     "- A value read by a script rather than printed by the shell.\n\n"
     "If Claude needs to know whether a variable is set, it can test for that without printing the value."),

    ("secrets.prompt", "Secrets", "Secrets pasted into the chat",
     "Stop a message that holds a key before it is sent, and say to rotate it.",
     "## How it works\n"
     "Before a message you send reaches the model, the hook reads it with the same detectors as the file rule: the known key formats, and NAME=value lines with a random value. If it finds one, the message is stopped. Claude Code erases it, and it is never sent. You see one line that names the kind of key and says what to do.\n\n"
     "## Why it exists\n"
     "A key pasted into the chat by mistake travels to the model with every later request, and the transcript keeps it. The moment before it is sent is the only moment it is still private.\n\n"
     "## Modes\n"
     "- deny: the message is stopped and never sent.\n"
     "- ask: the message goes through, and Claude is told to say that the key is now in the transcript and must be rotated.\n"
     "- off: nothing is checked.\n\n"
     "## What it does not catch\n"
     "- A key inside a file you point Claude at. The file rule handles that when Claude reads it.\n"
     "- A secret that reads as ordinary words.\n"
     "- A bare random string with no name in front of it and no known prefix, such as a raw base64 value on its own. Paste it as NAME=value and it is caught.\n\n"
     "## Safe alternative\n"
     "Remove the key from the message and send it again. To show a key on purpose, set the rule to ask for that one message, and back to deny after:\n"
     "cguard set secrets.prompt ask"),
    ("commit.secrets", "Commits", "Secrets in a commit",
     "Scan what git add or git commit is about to record and refuse it if a secret is in it.",
     "## How it works\n"
     "- On git add, the hook opens each file being added, or every file under a folder being added up to 500 files, and runs the same detectors as the secrets rule.\n"
     "- On git commit, it asks git for the staged diff, or the working-tree diff when -a is used, and scans the added lines only.\n\n"
     "A hit refuses the command and names the file.\n\n"
     "## Why it exists\n"
     "A secret in a commit is a secret in every clone, forever. Removing it later means rewriting history on every machine that pulled it.\n\n"
     "## What it does not catch\n"
     "- A secret that none of the detectors recognise.\n"
     "- Anything staged and pushed outside a Claude session.\n\n"
     "## Safe alternative\n"
     "Move the value into an ignored .env file or into the deployment platform, then commit again. A file that legitimately holds a token-shaped value, such as a test fixture, is allowed with:\n"
     "cguard allow commit_paths <path>"),
    ("commit.binaries", "Commits", "Documents and large files in a commit",
     "Refuse git add of PDFs, office documents, archives, databases, and anything over the size limit.",
     "## How it works\n"
     "On git add, and on git commit for files already staged, the hook checks each new file.\n\n"
     "- Its extension against the binary list: pdf, office documents, archives, databases, model files.\n"
     "- Its size against the limit, 5 MB by default.\n\n"
     "Both live in the configuration file. A path on the commit allowlist passes.\n\n"
     "## Why it exists\n"
     "Real documents end up in repositories by accident: a browser download folder still set to the project, a test file dropped in the wrong place. Once pushed, they are in history on every clone.\n\n"
     "## What it does not catch\n"
     "- A document with an extension that is not on the list.\n"
     "- A file under the size limit with a text extension.\n\n"
     "## Safe alternative\n"
     "Move the file out of the repository, or allow the exact path:\n"
     "cguard allow commit_paths <path>"),
    ("commit.add_all", "Commits", "git add -A and git add .",
     "Refuse blanket adds. Files are added by name.",
     "## How it works\n"
     "The hook refuses git add when its arguments contain -A, --all, . or *. Adding named paths passes, and so does git add -u, which touches tracked files only.\n\n"
     "## Why it exists\n"
     "A blanket add sweeps in everything in the working tree, including files you put there for other reasons. Adding by name forces a look at what is going in. It is the rule that stops the classic accident of committing a stray download.\n\n"
     "## Safe alternative\n"
     "Claude runs git status, then adds each intended path by name."),
    ("commit.no_verify", "Commits", "Skipping commit hooks",
     "Refuse git commit or git push with --no-verify.",
     "## How it works\n"
     "The hook refuses git commit and git push when their arguments contain --no-verify, or the short form -n on commit.\n\n"
     "## Why it exists\n"
     "That flag skips pre-commit and pre-push hooks, and those are usually exactly the checks that stop secrets and broken code from leaving the machine. If a hook is wrong, the hook gets fixed. If it must be skipped once, a person does it."),
    ("commit.force_push", "Commits", "Force push",
     "Ask before git push --force, -f or --force-with-lease.",
     "## How it works\n"
     "The hook asks for confirmation when a git push carries --force, -f, --force-with-lease, or a refspec that begins with +.\n\n"
     "## Why it exists\n"
     "A force push rewrites history that other clones may already hold. Sometimes it is the right thing, for example after removing a secret from history. It is never the routine thing, so a person confirms it each time and sees the full command."),

    ("commands.fatal", "Commands", "Commands that destroy a machine",
     "Refuse rm -rf on /, ~ or ., mkfs, dd onto a disk, fork bombs.",
     "## How it works\n"
     "The hook splits the shell line into commands and refuses these.\n\n"
     "- rm with a recursive flag whose target is /, /*, ~, $HOME, ., .., * or a top-level system folder.\n"
     "- mkfs in any form.\n"
     "- dd with a disk device as its output, or a redirect onto a disk device.\n"
     "- shred on a device.\n"
     "- chmod 777 on /.\n"
     "- The fork bomb.\n\n"
     "## Why it exists\n"
     "None of these has a legitimate use inside an assistant session, and none has an undo. If one is ever needed, a person types it in a terminal they are looking at.\n\n"
     "## What it does not catch\n"
     "- The same effect reached through a script.\n"
     "- A variable that expands to one of those targets.\n"
     "- A command the hook does not know.\n\n"
     "This is a list, not a proof."),
    ("commands.destructive", "Commands", "Commands that lose work",
     "Ask before git reset --hard, git clean -f, docker prune, DROP TABLE, terraform destroy, kubectl delete, migration resets and similar.",
     "## How it works\n"
     "The hook matches the shell line against a list of commands that throw something away, and asks for confirmation with the command shown in full.\n\n"
     "## The list\n"
     "- git reset --hard\n"
     "- git clean with -f\n"
     "- git checkout -- . and git restore ., which discard all changes\n"
     "- git branch -D\n"
     "- chmod -R 777 and chown -R\n"
     "- docker system prune, docker volume prune, docker image prune\n"
     "- docker run with --privileged or with the Docker socket mounted\n"
     "- DROP TABLE, DROP DATABASE, DROP SCHEMA, TRUNCATE\n"
     "- kill -9 -1\n"
     "- terraform destroy and terraform state rm\n"
     "- kubectl delete of a namespace, with -f, or with --all, and helm uninstall\n"
     "- prisma migrate reset, prisma db push --force-reset, rails db:drop, flyway clean, alembic downgrade base\n"
     "- docker compose down -v and docker volume rm\n"
     "- aws, gcloud, az, doctl, hcloud and fly commands that delete, terminate or destroy, plus aws s3 rb and aws s3 rm --recursive\n"
     "- dropdb and redis-cli flushall\n\n"
     "## Why it asks rather than refuses\n"
     "Each of these is legitimate often enough that a refusal would be an obstacle. What they share is that git or a backup may not have what they delete: uncommitted changes, untracked files, permissions, images and volumes, a table. A yes from a person who has read the command is the right price."),
    ("commands.sudo", "Commands", "sudo",
     "Ask before any command run as root.",
     "## How it works\n"
     "The hook asks for confirmation when a command, or any command in a chain, begins with sudo, doas or su.\n\n"
     "## Why it exists\n"
     "Root removes the last safety net under everything else on this list. The ask shows the full command so a person reads it before it runs with full rights.\n\n"
     "On a machine where Claude never needs root, set this to deny."),

    ("exfil.pipe_to_shell", "Data leaving", "Download piped into a shell",
     "Refuse curl or wget piped into a shell or interpreter that would run the download.",
     "## How it works\n"
     "The hook looks at every pipe in the line. When curl or wget feeds a command that runs its input as a script, the line is refused: sh, bash, zsh, fish, dash, python, perl, node or ruby with no script of their own, directly or through sudo. A pipe into a command that only reads the data passes, such as python3 -c, python3 -m json.tool, perl -ne, node -e or jq. bash -c \"$(curl ...)\" and bash <(curl ...) run a download as code too, and are refused.\n\n"
     "## Why it exists\n"
     "curl URL | sh downloads a script and runs it before anyone has read it. It is how many tools tell you to install them, and it is also the most common way a developer machine is compromised.\n\n"
     "## Safe alternative\n"
     "Claude downloads the script to a file, tells you where it is so you can read it, then runs it from the file."),
    ("exfil.upload", "Data leaving", "Sending files to another host",
     "Ask before curl uploads, scp, rsync, sftp or nc to a host that is not on the allowlist.",
     "## How it works\n"
     "The hook looks for three shapes, reads the host out of the command, and asks unless that host is localhost or on the allowlist.\n\n"
     "- curl with a data or upload flag: -d, --data-binary, -F, -T, --upload-file.\n"
     "- scp, rsync or sftp with a host:path argument.\n"
     "- nc, ncat, netcat or socat with a host.\n\n"
     "## Why it exists\n"
     "A file leaving the machine should be a decision, not a side effect of a command that looked routine.\n\n"
     "## What it does not catch\n"
     "- An upload done by a program Claude wrote.\n"
     "- A host hidden in a variable.\n"
     "- Tools not on the list.\n\n"
     "## Safe alternative\n"
     "Add your own machines once:\n"
     "cguard allow hosts <host>"),

    ("self.protect", "The guard itself", "Protect the guard and the credentials",
     "Refuse edits to the plugin, its configuration file, Claude Code's own configuration and the credentials file.",
     "## How it works\n"
     "The hook refuses Edit and Write on four places, and shell commands that both name one of them and contain a way of writing to it: a redirect, sed -i, tee, rm, mv, cp, truncate, chmod, or an interpreter. It also refuses `cguard set self.protect off` and `cguard denylist install` or `remove` from inside a session; those are yours to run in a terminal. Setting the rule back to deny is allowed from a session.\n\n"
     "- The plugin's own files.\n"
     "- Its configuration file.\n"
     "- Claude Code's configuration file.\n"
     "- The credentials file.\n\n"
     "Reading them is allowed. The cguard command line is allowed, because that is the intended way to change the configuration.\n\n"
     "## Why it exists\n"
     "A prompt injection that says \"first disable the security hook\" should have nowhere to go.\n\n"
     "## Safe alternative\n"
     "Changes go through the tool, which Claude runs only when you ask:\n"
     "cguard set <rule> <mode>\n"
     "cguard allow <list> <value>\n"
     "cguard profile <name>"),

    ("paths.boundary", "Boundary", "Stay inside the project",
     "Ask before touching a file outside the working directory and the allowed folders.",
     "## How it works\n"
     "- For Read, Edit, Write and Grep the hook checks the target path.\n"
     "- For a shell command it checks every argument that names an existing file or folder.\n\n"
     "A path outside the working directory asks for confirmation, unless it is under the Claude configuration folder, /tmp, or a folder on the allowlist.\n\n"
     "## Why it exists\n"
     "A session opened in one project has no business in the rest of the machine: a browser profile, a different project, a folder of documents. When every folder on the machine is part of the work this is more obstacle than protection, which is why the standard profile leaves it off and the contained profile sets it to ask.\n\n"
     "## Safe alternative\n"
     "Open a Claude session in that folder instead, or allow the folder:\n"
     "cguard allow paths <folder>"),
    ("packages.install", "Boundary", "Installing packages",
     "Ask before pip install, npm install, npx, cargo install, brew, pacman, apt and similar.",
     "## How it works\n"
     "The hook matches the shell line against the install commands of the common package managers and asks for confirmation with the command shown.\n\n"
     "- pip, uv\n"
     "- npm, pnpm, yarn, bun, npx\n"
     "- cargo, go\n"
     "- brew, pacman, paru, yay, apt\n"
     "- gem\n\n"
     "## Why it exists\n"
     "Every install pulls code from the internet onto the machine, and an assistant can do it dozens of times an hour without anyone noticing what arrived.\n\n"
     "Off by default on the standard profile, ask on the contained profile."),

    ("session.check", "Session", "Hygiene check at session start",
     "At session start, warn once if .env is not ignored or a tracked file looks like it holds a secret.",
     "## How it works\n"
     "Once per session, in the repository the session opened in, the hook does two checks.\n\n"
     "- That .env appears in .gitignore.\n"
     "- That no tracked file, up to 500, holds secret material by the same detectors as the secrets rule.\n\n"
     "If something is found, one warning line is added to the session's context and Claude tells you once.\n\n"
     "## Modes\n"
     "Deny and ask both mean on. Off by default because it costs a few tokens per session."),
]

GROUPS = []
for _r in RULES:
    if _r[1] not in GROUPS:
        GROUPS.append(_r[1])

PROFILES = {
    "standard": {
        "secrets.files": "deny", "secrets.write": "deny", "secrets.env": "deny", "secrets.prompt": "deny",
        "commit.secrets": "deny", "commit.binaries": "deny", "commit.add_all": "deny",
        "commit.no_verify": "deny", "commit.force_push": "ask",
        "commands.fatal": "deny", "commands.destructive": "ask", "commands.sudo": "ask",
        "exfil.pipe_to_shell": "deny", "exfil.upload": "ask",
        "self.protect": "deny",
        "paths.boundary": "off", "packages.install": "off",
        "session.check": "off",
    },
    "contained": {
        "secrets.files": "deny", "secrets.write": "deny", "secrets.env": "deny", "secrets.prompt": "deny",
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


def parse_markup(text):
    """[(style, text)] with style in header, bullet, para, blank. Consecutive plain lines join."""
    out, para = [], []

    def flush():
        if para:
            out.append(("para", " ".join(para)))
            para.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            flush()
            out.append(("blank", ""))
        elif stripped.startswith("## "):
            flush()
            out.append(("header", stripped[3:]))
        elif stripped.startswith("- "):
            flush()
            out.append(("bullet", stripped[2:]))
        else:
            para.append(stripped)
    flush()
    return out


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
