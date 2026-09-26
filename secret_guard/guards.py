"""The guards. Each one looks at a single tool call and returns a Decision or None.

A Decision carries the rule, the mode (deny or ask), what was blocked, why in one line,
what the user can do themselves, and how to allow it. The hook turns that into the
reason Claude reads, so no refusal ever arrives without a way forward.
"""
import glob
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import config, patterns

MAX_WALK = 500          # files scanned when a directory is added
MAX_TOKENS = 200


@dataclass
class Decision:
    rule: str
    mode: str
    what: str
    why: str
    do_yourself: str = ""
    allow_hint: str = ""

    def reason(self):
        lines = [f"secret-guard {self.mode} [{self.rule}]: {self.what}", f"Why: {self.why}"]
        if self.do_yourself:
            lines.append(f"Do it yourself: {self.do_yourself}")
        if self.allow_hint:
            lines.append(f"Or allow it: {self.allow_hint}")
        lines.append("Relay all of this to the user. Do not retry the same call.")
        return "\n".join(lines)


# ----------------------------------------------------------------------------- helpers

def _protected_paths():
    home = Path(os.path.expanduser("~"))
    claude = home / ".claude"
    return [Path(config.PLUGIN_ROOT).resolve(), config.CONFIG_PATH.resolve(),
            (claude / "settings.json").resolve(), (claude / (".credentials" + ".json")).resolve(),
            (claude / "hooks").resolve()]


def _under(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except (ValueError, OSError):
        return False


def _is_protected(path):
    p = Path(path)
    for prot in _protected_paths():
        if p.resolve() == prot or (prot.is_dir() and _under(p, prot)):
            return prot
    return None


def _cli_token(token):
    return token.endswith("/cli.py") or token.endswith("/bin/secret-guard") or token == "secret-guard"


def _allowed_path(cfg, path):
    for allowed in cfg["lists"]["paths"]:
        if Path(path).resolve() == Path(allowed).resolve() or (os.path.isdir(allowed) and _under(path, allowed)):
            return True
    return False


def _boundary_roots(cfg, cwd):
    roots = [cwd, os.path.realpath(cwd), os.path.expanduser("~/.claude"), "/tmp", "/var/tmp", "/dev",
             "/proc/self"] + list(cfg["lists"]["paths"])
    scratch = os.environ.get("CLAUDE_SCRATCHPAD")
    if scratch:
        roots.append(scratch)
    return roots


def _outside(cfg, cwd, path):
    if not os.path.exists(path):
        return False
    for root in _boundary_roots(cfg, cwd):
        if _under(path, root):
            return False
    return True


def _expand(token, cwd):
    token = os.path.expanduser(os.path.expandvars(token))
    if not os.path.isabs(token):
        token = os.path.join(cwd, token)
    return glob.glob(token) or [token]


def _path_tokens(command, cwd):
    """Absolute candidates for every token that looks like a path."""
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()
    out = []
    for token in tokens[:MAX_TOKENS]:
        for piece in re.split(r"[=;|&<>(),]", token):
            if not piece or piece.startswith("-") or "://" in piece:
                continue
            looks_like_path = "/" in piece or piece.startswith("~") or piece.startswith("$") \
                or os.path.isfile(os.path.join(cwd, piece))
            if looks_like_path:
                out.extend(_expand(piece, cwd))
    return out


def _segments(command):
    """Split a shell line on && || ; | into simple commands, each as a token list."""
    parts = re.split(r"\|\||&&|;|\|", command)
    out = []
    for part in parts:
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError:
            tokens = part.split()
        # drop leading env assignments and sudo, keep sudo visible to its own guard
        out.append(tokens)
    return out


def _host_allowed(cfg, host):
    host = host.strip("[]").lower()
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or host.startswith("127."):
        return True
    for allowed in cfg["lists"]["hosts"]:
        a = allowed.lower()
        if host == a or host.endswith("." + a):
            return True
    return False


def _git_subcommand(tokens):
    """(subcommand, args, repo_dir_override) for a git token list, else (None, [], None)."""
    if not tokens or tokens[0] != "git":
        return None, [], None
    i, repo = 1, None
    while i < len(tokens):
        t = tokens[i]
        if t == "-C" and i + 1 < len(tokens):
            repo = tokens[i + 1]; i += 2; continue
        if t == "-c" and i + 1 < len(tokens):
            i += 2; continue
        if t.startswith("-"):
            i += 1; continue
        return t, tokens[i + 1:], repo
    return None, [], repo


def _commit_allowed(cfg, cwd, path):
    rel = os.path.relpath(path, cwd)
    for allowed in cfg["lists"]["commit_paths"]:
        if rel == allowed or path == allowed or glob.fnmatch.fnmatch(rel, allowed):
            return True
    return False


def _binary_reason(cfg, path):
    ext = os.path.splitext(path)[1].lower()
    if ext in cfg["lists"]["binary_extensions"]:
        return f"{os.path.basename(path)} is a {ext} file"
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    limit = float(cfg["lists"]["max_file_mb"]) * 1024 * 1024
    if size > limit:
        return f"{os.path.basename(path)} is {size / (1024 * 1024):.1f} MB, above the {cfg['lists']['max_file_mb']} MB limit"
    return None


def _files_under(path):
    if os.path.isfile(path):
        return [path]
    out = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__")]
        for f in files:
            out.append(os.path.join(root, f))
            if len(out) >= MAX_WALK:
                return out
    return out


def _run_git(repo, args, timeout=8):
    try:
        r = subprocess.run(["git", "-C", repo] + args, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ----------------------------------------------------------------------------- the guards

def _dec(cfg, rule, what, why, do_yourself="", allow_hint=""):
    mode = cfg["rules"].get(rule, "off")
    if mode == "off":
        return None
    return Decision(rule, mode, what, why, do_yourself, allow_hint)


def check_file_tools(tool, tool_input, cwd, cfg):
    target = tool_input.get("file_path") or tool_input.get("path")
    text = (tool_input.get("content") or "") + (tool_input.get("new_string") or "")

    if target:
        for candidate in _expand(str(target), cwd):
            prot = _is_protected(candidate)
            if prot and tool in ("Edit", "Write"):
                d = _dec(cfg, "self.protect",
                         f"editing {candidate}, which belongs to the guard or holds credentials.",
                         "the guard's own files and the credentials must not be changed from inside a session.",
                         "run `secret-guard config` in a terminal for the settings screen.",
                         "ask me to run `secret-guard set <rule> <mode>` or `secret-guard allow <list> <value>`; those go through the tool, not the file.")
                if d:
                    return d
            if not _allowed_path(cfg, candidate):
                label = patterns.classify_file(candidate)
                if label:
                    d = _dec(cfg, "secrets.files",
                             f"{tool} on {candidate}, which contains {label}.",
                             "secret material is never read or modified by Claude; the file content did not reach the model.",
                             f"open it yourself: `${{EDITOR:-nano}} {candidate}`. If you need me to work on it, remove the secret first or paste the non-secret parts.",
                             f"`secret-guard allow paths {candidate}`")
                    if d:
                        return d
            if _outside(cfg, cwd, candidate):
                d = _dec(cfg, "paths.boundary",
                         f"{tool} on {candidate}, outside the project {cwd}.",
                         "a session stays inside the folder it was opened in unless a folder is allowed.",
                         f"open a Claude session in that folder: `cd {os.path.dirname(candidate)} && claude`.",
                         f"`secret-guard allow paths {os.path.dirname(candidate)}`")
                if d:
                    return d

    if text and patterns.WRITE_PATTERN.search(text):
        return _dec(cfg, "secrets.write", "writing private key material into a file.",
                    "a key that Claude writes was in the transcript first; keys are generated by tools, never typed.",
                    "generate the key yourself, for example `ssh-keygen -t ed25519 -f ~/.ssh/<name>`.", "")
    return None


FATAL_TARGETS = {"/", "/*", "~", "~/", "~/*", "$HOME", "$HOME/", "${HOME}", ".", "./", "..", "*", "/home", "/etc", "/usr", "/var"}
FATAL_RE = [
    (re.compile(r"\bmkfs(\.\w+)?\b"), "mkfs formats a disk"),
    (re.compile(r"\bdd\b[^|;&]*\bof=/dev/(sd|nvme|vd|hd|disk|mmcblk)"), "dd onto a disk device overwrites it"),
    (re.compile(r">\s*/dev/(sd|nvme|vd|hd|mmcblk)"), "writing to a disk device overwrites it"),
    (re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"), "this is a fork bomb"),
    (re.compile(r"\bshred\b[^|;&]*\s/dev/"), "shred on a device destroys it"),
    (re.compile(r"\bchmod\s+(-R|--recursive)\s+[0-7]*777\s+/(\s|$)"), "chmod 777 on / opens every file on the machine"),
]

DESTRUCTIVE_RE = [
    (re.compile(r"\bgit\b[^|;&]*\breset\s+--hard\b"), "git reset --hard discards every uncommitted change"),
    (re.compile(r"\bgit\b[^|;&]*\bclean\b[^|;&]*\s-[a-zA-Z]*f"), "git clean -f deletes untracked files, ignored ones too with -x"),
    (re.compile(r"\bgit\b[^|;&]*\b(checkout|restore)\s+(--\s+)?\.(\s|$)"), "this discards all changes in the working tree"),
    (re.compile(r"\bgit\b[^|;&]*\bbranch\s+(-D|--delete\s+--force)\b"), "git branch -D deletes a branch whether or not it is merged"),
    (re.compile(r"\bchmod\s+(-R|--recursive)\b[^|;&]*\b[0-7]*777\b"), "chmod -R 777 makes a whole tree writable by everyone"),
    (re.compile(r"\bchown\s+(-R|--recursive)\b"), "chown -R changes ownership of a whole tree"),
    (re.compile(r"\bdocker\s+(system|volume|image|container)\s+prune\b"), "docker prune deletes images, volumes or containers"),
    (re.compile(r"\bdocker\s+run\b[^|;&]*(--privileged|/var/run/docker\.sock)"), "this container gets full control of the host"),
    (re.compile(r"(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b"), "DROP deletes a table or database"),
    (re.compile(r"(?i)\bTRUNCATE\s+(TABLE\s+)?\w"), "TRUNCATE empties a table"),
    (re.compile(r"\bkill\s+-9\s+-1\b"), "kill -9 -1 kills every process you own"),
]

PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(sh|bash|zsh|fish|dash|python3?|perl|node|ruby)\b")
UPLOAD_FLAGS = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "--data-ascii", "-F", "--form",
                "-T", "--upload-file", "--json"}
REMOTE_COPY = {"scp", "rsync", "sftp"}
RAW_NET = {"nc", "ncat", "netcat", "socat"}
HOSTSPEC = re.compile(r"^(?:[\w.\-]+@)?([\w.\-]{2,}):")
URL_HOST = re.compile(r"^[a-z][a-z0-9+.\-]*://(?:[^@/\s]+@)?([^/:\s]+)", re.I)
ENV_PRINT = re.compile(r"(?:^|\s)(?:echo|printf|print)\b[^|;&]*\$\{?([A-Za-z_][A-Za-z0-9_]*)")
PACKAGE_RE = re.compile(
    r"\b(?:pip3?|uv)\s+(?:install|add)\b|\buv\s+pip\s+install\b|\bnpm\s+(?:install|i|add|ci)\b|\bpnpm\s+(?:add|install|i)\b|"
    r"\byarn\s+(?:add|install)\b|\bbun\s+(?:add|install)\b|\bnpx\s+(?!--no-install)\S|\bcargo\s+install\b|\bgo\s+install\b|"
    r"\bbrew\s+install\b|\bpacman\s+-S\b|\bparu\s+-S\b|\byay\s+-S\b|\bapt(?:-get)?\s+install\b|\bgem\s+install\b")


def check_bash(command, cwd, cfg):
    if not command.strip():
        return None
    segments = _segments(command)
    all_tokens = [t for seg in segments for t in seg]

    # The guard itself
    for token in all_tokens:
        if _cli_token(token):
            continue
        for candidate in _expand(token, cwd) if ("/" in token or token.startswith("~")) else []:
            if _is_protected(candidate) and re.search(r">|\bsed\s+-i|\btee\b|\brm\b|\bmv\b|\bcp\b|\btruncate\b|\bchmod\b|\bpython3?\b|\bperl\b|\binstall\b", command):
                d = _dec(cfg, "self.protect", f"a command that writes to {candidate}, which belongs to the guard or holds credentials.",
                         "the guard's own files and the credentials are not changed from inside a session.",
                         "run `secret-guard config` in a terminal.",
                         "ask me to run `secret-guard set <rule> <mode>` instead.")
                if d:
                    return d

    # Commands that destroy a machine
    for seg in segments:
        if seg and seg[0] == "rm" or (len(seg) > 1 and seg[0] == "sudo" and "rm" in seg[:3]):
            flags = "".join(t.lstrip("-") for t in seg if t.startswith("-") and not t.startswith("--"))
            recursive = "r" in flags or "R" in flags or "--recursive" in seg
            force = "f" in flags or "--force" in seg
            targets = [t for t in seg[1:] if not t.startswith("-") and t not in ("sudo",)]
            if recursive and any(t in FATAL_TARGETS or os.path.expanduser(t) in (os.path.expanduser("~"), "/") for t in targets):
                d = _dec(cfg, "commands.fatal", f"`{' '.join(seg)}` deletes everything under {', '.join(targets)}.",
                         "this cannot be undone and has no place inside an assistant session.",
                         "if you really mean it, type it yourself in a terminal you are looking at.", "")
                if d:
                    return d
    for pattern, why in FATAL_RE:
        if pattern.search(command):
            d = _dec(cfg, "commands.fatal", f"`{command.strip()[:120]}`", why + ", and it cannot be undone.",
                     "if you really mean it, type it yourself in a terminal you are looking at.", "")
            if d:
                return d

    # Commands that lose work
    for pattern, why in DESTRUCTIVE_RE:
        if pattern.search(command):
            d = _dec(cfg, "commands.destructive", f"`{command.strip()[:120]}`", why + ".",
                     "run it yourself if the loss is intended.", "`secret-guard set commands.destructive off`")
            if d:
                return d

    # Download piped into a shell
    if PIPE_TO_SHELL.search(command):
        d = _dec(cfg, "exfil.pipe_to_shell", "a download piped straight into an interpreter.",
                 "the script runs before anyone has read it; this is how machines get compromised.",
                 "download it to a file first, for example `curl -fsSL <url> -o /tmp/install.sh`, read it, then run it from the file.",
                 "`secret-guard set exfil.pipe_to_shell off`")
        if d:
            return d

    # sudo
    if any(seg and seg[0] in ("sudo", "doas") or (seg and seg[0] == "su") for seg in segments):
        d = _dec(cfg, "commands.sudo", f"`{command.strip()[:120]}` runs as root.",
                 "root removes every other safety net.",
                 f"open a terminal and run it yourself: `cd {cwd}` then the command above.",
                 "`secret-guard set commands.sudo off`")
        if d:
            return d

    # Environment variables
    for seg in segments:
        if not seg:
            continue
        head = seg[0]
        args = [a for a in seg[1:] if not a.startswith("-")]
        if head in ("env", "printenv") and (not args or any(patterns.SECRET_NAME.search(a) for a in args)):
            d = _dec(cfg, "secrets.env", f"`{' '.join(seg)}` prints environment variables into the transcript.",
                     "API keys live in the environment, and the transcript leaves the machine with every request.",
                     "run it yourself in a terminal; if I need one non-secret value, tell me its name and I will print only that.",
                     "`secret-guard set secrets.env off`")
            if d:
                return d
        if head == "export" and "-p" in seg:
            d = _dec(cfg, "secrets.env", "`export -p` prints every exported variable.",
                     "that includes every key in the environment.", "run it yourself in a terminal.", "`secret-guard set secrets.env off`")
            if d:
                return d
    for m in ENV_PRINT.finditer(command):
        if patterns.SECRET_NAME.search(m.group(1)):
            d = _dec(cfg, "secrets.env", f"printing ${m.group(1)} into the transcript.",
                     "its name says it is a secret, and the transcript leaves the machine.",
                     f"check it yourself: `test -n \"${m.group(1)}\" && echo set || echo unset`.", "`secret-guard set secrets.env off`")
            if d:
                return d
    if re.search(r"/proc/(\d+|self)/environ", command):
        d = _dec(cfg, "secrets.env", "reading a process environment from /proc.", "that is every variable of that process, keys included.",
                 "read it yourself in a terminal.", "`secret-guard set secrets.env off`")
        if d:
            return d

    # Git
    for seg in segments:
        sub, args, repo = _git_subcommand(seg)
        if not sub:
            continue
        repo_dir = os.path.abspath(os.path.join(cwd, repo)) if repo else cwd
        if sub == "add":
            if any(a in ("-A", "--all", ".", "./", "*", ":/") for a in args):
                d = _dec(cfg, "commit.add_all", f"`{' '.join(seg)}` adds everything in the working tree.",
                         "blanket adds are how stray downloads and local files end up in history.",
                         "", "")
                if d:
                    d.do_yourself = f"run `git -C {repo_dir} status --short`, then add each intended path by name."
                    return d
            for a in args:
                if a.startswith("-"):
                    continue
                for candidate in _expand(a, repo_dir):
                    for f in _files_under(candidate):
                        if _commit_allowed(cfg, repo_dir, f):
                            continue
                        why = _binary_reason(cfg, f)
                        if why:
                            d = _dec(cfg, "commit.binaries", f"`git add` of {f}: {why}.",
                                     "documents and large files in a repository are usually accidents, and history keeps them forever.",
                                     f"move it out: `mv {f} ~/`  and add the rest by name.",
                                     f"`secret-guard allow commit_paths {os.path.relpath(f, repo_dir)}`")
                            if d:
                                return d
                        label = patterns.classify_file(f)
                        if label:
                            d = _dec(cfg, "commit.secrets", f"`git add` of {f}, which contains {label}.",
                                     "a secret in a commit is a secret in every clone, forever.",
                                     f"move the value into an ignored .env or into the deployment platform, then add the file again.",
                                     f"`secret-guard allow commit_paths {os.path.relpath(f, repo_dir)}`")
                            if d:
                                return d
        elif sub == "commit":
            if "--no-verify" in args or "-n" in args:
                d = _dec(cfg, "commit.no_verify", "`git commit --no-verify` skips the commit hooks.",
                         "those hooks are usually the checks that stop secrets and broken code from leaving the machine.",
                         "if a hook is wrong, fix the hook; if it must be skipped once, run the commit yourself.", "`secret-guard set commit.no_verify off`")
                if d:
                    return d
            if cfg["rules"].get("commit.secrets") != "off" or cfg["rules"].get("commit.binaries") != "off":
                staged_all = "-a" in args or "--all" in args or any(a.startswith("-a") and not a.startswith("--") and "a" in a for a in args if a.startswith("-") and len(a) <= 4)
                diff_args = ["diff", "-U0", "--no-color", "HEAD"] if staged_all else ["diff", "--cached", "-U0", "--no-color"]
                diff = _run_git(repo_dir, diff_args)
                current, added = None, {}
                for line in diff.splitlines():
                    if line.startswith("+++ b/"):
                        current = line[6:]
                    elif line.startswith("+") and not line.startswith("+++") and current:
                        added.setdefault(current, []).append(line[1:])
                for f, lines in added.items():
                    full = os.path.join(repo_dir, f)
                    if _commit_allowed(cfg, repo_dir, full):
                        continue
                    label = patterns.find_secret("\n".join(lines))
                    if label:
                        d = _dec(cfg, "commit.secrets", f"the staged change to {f} contains {label}.",
                                 "a secret in a commit is a secret in every clone, forever.",
                                 f"remove it: `git -C {repo_dir} restore --staged {f}`, move the value into an ignored .env, then stage the file again.",
                                 f"`secret-guard allow commit_paths {f}`")
                        if d:
                            return d
                names = _run_git(repo_dir, ["diff", "--cached", "--name-only", "--diff-filter=A"] if not staged_all else ["diff", "--name-only", "--diff-filter=A", "HEAD"])
                for f in names.splitlines():
                    full = os.path.join(repo_dir, f)
                    if not os.path.isfile(full) or _commit_allowed(cfg, repo_dir, full):
                        continue
                    why = _binary_reason(cfg, full)
                    if why:
                        d = _dec(cfg, "commit.binaries", f"the commit would add {f}: {why}.",
                                 "documents and large files in a repository are usually accidents, and history keeps them forever.",
                                 f"unstage it: `git -C {repo_dir} restore --staged {f}` and move the file out of the repository.",
                                 f"`secret-guard allow commit_paths {f}`")
                        if d:
                            return d
        elif sub == "push":
            if "--no-verify" in args:
                d = _dec(cfg, "commit.no_verify", "`git push --no-verify` skips the push hooks.",
                         "those hooks exist to stop bad pushes.", "run the push yourself if it must be skipped once.", "`secret-guard set commit.no_verify off`")
                if d:
                    return d
            if any(a in ("--force", "-f", "--force-with-lease") or a.startswith("--force-with-lease=") or (a.startswith("+") and ":" in a) for a in args):
                d = _dec(cfg, "commit.force_push", f"`{' '.join(seg)}` rewrites history on the remote.",
                         "other clones and other people may hold the history being replaced.",
                         "run it yourself once you have confirmed nobody else has pulled.", "`secret-guard set commit.force_push off`")
                if d:
                    return d

    # Data leaving the machine
    for seg in segments:
        if not seg:
            continue
        head = seg[0] if seg[0] not in ("sudo", "env", "nohup", "time") or len(seg) < 2 else seg[1]
        if head == "curl" and any(t in UPLOAD_FLAGS or t.startswith("--data") for t in seg):
            hosts = [URL_HOST.match(t).group(1) for t in seg if URL_HOST.match(t)]
            if not hosts or not all(_host_allowed(cfg, h) for h in hosts):
                d = _dec(cfg, "exfil.upload", f"`{' '.join(seg)[:120]}` sends data to {', '.join(hosts) or 'an unknown host'}.",
                         "data leaving the machine should be a decision, not a side effect.",
                         "run it yourself in a terminal if the destination is right.",
                         f"`secret-guard allow hosts {hosts[0]}`" if hosts else "`secret-guard set exfil.upload off`")
                if d:
                    return d
        if head in REMOTE_COPY:
            hosts = [HOSTSPEC.match(t).group(1) for t in seg[1:] if not t.startswith("-") and HOSTSPEC.match(t) and "/" not in t.split(":")[0]]
            if hosts and not all(_host_allowed(cfg, h) for h in hosts):
                d = _dec(cfg, "exfil.upload", f"`{' '.join(seg)[:120]}` copies files to {', '.join(hosts)}.",
                         "files leaving the machine should be a decision, not a side effect.",
                         "run it yourself in a terminal if the destination is right.", f"`secret-guard allow hosts {hosts[0]}`")
                if d:
                    return d
        if head in RAW_NET:
            args = [t for t in seg[1:] if not t.startswith("-")]
            host = args[0] if args else ""
            if host and not _host_allowed(cfg, host):
                d = _dec(cfg, "exfil.upload", f"`{' '.join(seg)[:120]}` opens a raw connection to {host}.",
                         "a raw socket can carry anything out of the machine.", "run it yourself in a terminal.", f"`secret-guard allow hosts {host}`")
                if d:
                    return d

    # Packages
    m = PACKAGE_RE.search(command)
    if m:
        d = _dec(cfg, "packages.install", f"`{command.strip()[:120]}` installs code from the internet.",
                 "every install brings code onto the machine that nobody here has read.",
                 "run the install yourself after a look at the package page.", "`secret-guard set packages.install off`")
        if d:
            return d

    # Files named in the command
    for candidate in sorted(set(_path_tokens(command, cwd))):
        if _allowed_path(cfg, candidate):
            continue
        label = patterns.classify_file(candidate)
        if label:
            d = _dec(cfg, "secrets.files", f"this command touches {candidate}, which contains {label}.",
                     "secret material is never read by Claude; the content did not reach the model.",
                     f"run it yourself in a terminal, or move the secret out of {os.path.basename(candidate)} first.",
                     f"`secret-guard allow paths {candidate}`")
            if d:
                return d
        if _outside(cfg, cwd, candidate):
            d = _dec(cfg, "paths.boundary", f"this command touches {candidate}, outside the project {cwd}.",
                     "a session stays inside the folder it was opened in unless a folder is allowed.",
                     f"run it yourself, or open a Claude session there: `cd {candidate if os.path.isdir(candidate) else os.path.dirname(candidate)} && claude`.",
                     f"`secret-guard allow paths {candidate if os.path.isdir(candidate) else os.path.dirname(candidate)}`")
            if d:
                return d
    return None


def evaluate(data, cfg):
    """A Decision for this tool call, or None to let it through."""
    tool = data.get("tool_name", "")
    tool_input = data.get("tool_input") or {}
    cwd = data.get("cwd") or os.getcwd()
    if tool in ("Read", "Edit", "Write", "Grep", "MultiEdit", "NotebookEdit"):
        return check_file_tools(tool, tool_input, cwd, cfg)
    if tool == "Bash":
        return check_bash(tool_input.get("command", ""), cwd, cfg)
    return None


def session_check(cwd, cfg):
    """One warning line for the session, or None."""
    if cfg["rules"].get("session.check") == "off":
        return None
    problems = []
    gitignore = os.path.join(cwd, ".gitignore")
    if os.path.isdir(os.path.join(cwd, ".git")):
        ignored = ""
        try:
            ignored = open(gitignore, encoding="utf-8").read()
        except OSError:
            pass
        if ".env" not in ignored:
            problems.append(".env is not in .gitignore")
        tracked = _run_git(cwd, ["ls-files"]).splitlines()[:500]
        for f in tracked:
            label = patterns.classify_file(os.path.join(cwd, f))
            if label:
                problems.append(f"tracked file {f} contains {label}")
                break
    if not problems:
        return None
    return "secret-guard session check: " + "; ".join(problems) + ". Tell the user once, then continue."
