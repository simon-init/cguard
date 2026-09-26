"""Known secret paths: the deny rules for Claude Code's own permissions.

The plugin's hook finds secrets by content. These rules block files by name before any
hook runs: SSH keys, environment files, cloud and password-manager credentials, shell
history, browser profiles, and the commands that would print them. They live in the
user's Claude Code settings file, which a plugin cannot write on its own, so cguard
carries them as data and installs them on request.
"""
import json
import os
from pathlib import Path

SETTINGS_PATH = Path(os.environ.get("CGUARD_SETTINGS") or os.path.expanduser("~/.claude/settings.json"))

RULES = [
    "Read(~/.ssh)",
    "Read(~/.ssh/**)",
    "Edit(~/.ssh)",
    "Edit(~/.ssh/**)",
    "Write(~/.ssh)",
    "Write(~/.ssh/**)",
    "Bash(*/.ssh*)",
    "Read(//**/.env)",
    "Read(//**/.env.local)",
    "Read(//**/.env.production)",
    "Read(//**/.env.*.local)",
    "Read(//**/.backup-env)",
    "Edit(//**/.env)",
    "Edit(//**/.env.local)",
    "Edit(//**/.env.production)",
    "Edit(//**/.env.*.local)",
    "Edit(//**/.backup-env)",
    "Write(//**/.env)",
    "Write(//**/.env.local)",
    "Write(//**/.env.production)",
    "Write(//**/.env.*.local)",
    "Write(//**/.backup-env)",
    "Bash(*cat *.env*)",
    "Bash(*bat *.env*)",
    "Bash(*less *.env*)",
    "Bash(*head *.env*)",
    "Bash(*tail *.env*)",
    "Bash(*grep *.env*)",
    "Bash(*source *.env*)",
    "Bash(*. *.env*)",
    "Read(//**/*.pem)",
    "Read(//**/*.key)",
    "Read(//**/*.p12)",
    "Read(//**/*.pfx)",
    "Read(//**/*.kdbx)",
    "Read(//**/id_rsa*)",
    "Read(//**/id_ed25519*)",
    "Read(//**/*.tfstate)",
    "Read(//**/*.tfvars)",
    "Edit(//**/*.pem)",
    "Edit(//**/*.key)",
    "Edit(//**/*.p12)",
    "Edit(//**/*.pfx)",
    "Edit(//**/*.kdbx)",
    "Edit(//**/id_rsa*)",
    "Edit(//**/id_ed25519*)",
    "Edit(//**/*.tfstate)",
    "Edit(//**/*.tfvars)",
    "Write(//**/*.pem)",
    "Write(//**/*.key)",
    "Write(//**/*.p12)",
    "Write(//**/*.pfx)",
    "Write(//**/*.kdbx)",
    "Write(//**/id_rsa*)",
    "Write(//**/id_ed25519*)",
    "Write(//**/*.tfstate)",
    "Write(//**/*.tfvars)",
    "Read(~/.aws/**)",
    "Read(~/.azure/**)",
    "Read(~/.config/gcloud/**)",
    "Read(~/.config/hcloud/**)",
    "Read(~/.kube/**)",
    "Read(~/.gnupg/**)",
    "Read(~/.docker/config.json)",
    "Read(~/.netrc)",
    "Read(~/.git-credentials)",
    "Read(~/.password-store/**)",
    "Read(~/.config/Bitwarden CLI/**)",
    "Read(~/.config/rclone/**)",
    "Read(~/.config/sops/**)",
    "Read(~/.terraform.d/**)",
    "Read(~/.claude/.credentials.json)",
    "Edit(~/.aws/**)",
    "Edit(~/.azure/**)",
    "Edit(~/.config/gcloud/**)",
    "Edit(~/.config/hcloud/**)",
    "Edit(~/.kube/**)",
    "Edit(~/.gnupg/**)",
    "Edit(~/.docker/config.json)",
    "Edit(~/.netrc)",
    "Edit(~/.git-credentials)",
    "Edit(~/.password-store/**)",
    "Edit(~/.config/Bitwarden CLI/**)",
    "Edit(~/.config/rclone/**)",
    "Edit(~/.config/sops/**)",
    "Edit(~/.terraform.d/**)",
    "Edit(~/.claude/.credentials.json)",
    "Write(~/.aws/**)",
    "Write(~/.azure/**)",
    "Write(~/.config/gcloud/**)",
    "Write(~/.config/hcloud/**)",
    "Write(~/.kube/**)",
    "Write(~/.gnupg/**)",
    "Write(~/.docker/config.json)",
    "Write(~/.netrc)",
    "Write(~/.git-credentials)",
    "Write(~/.password-store/**)",
    "Write(~/.config/Bitwarden CLI/**)",
    "Write(~/.config/rclone/**)",
    "Write(~/.config/sops/**)",
    "Write(~/.terraform.d/**)",
    "Write(~/.claude/.credentials.json)",
    "Bash(*/.aws*)",
    "Bash(*/.azure*)",
    "Bash(*/.config/gcloud*)",
    "Bash(*/.config/hcloud*)",
    "Bash(*/.kube*)",
    "Bash(*/.gnupg*)",
    "Bash(*/.docker/config.json*)",
    "Bash(*/.netrc*)",
    "Bash(*/.git-credentials*)",
    "Bash(*/.password-store*)",
    "Bash(*/.credentials.json*)",
    "Read(~/.bash_history)",
    "Read(~/.zsh_history)",
    "Read(~/.local/share/fish/fish_history)",
    "Read(~/.python_history)",
    "Read(~/.psql_history)",
    "Read(~/.mysql_history)",
    "Bash(*/.bash_history*)",
    "Bash(*/.zsh_history*)",
    "Bash(*fish_history*)",
    "Bash(*/.psql_history*)",
    "Read(~/.mozilla/**)",
    "Read(~/.config/chromium/**)",
    "Read(~/.config/google-chrome/**)",
    "Read(~/.config/BraveSoftware/**)",
    "Bash(*/.mozilla*)",
    "Bash(*/.config/chromium*)",
    "Bash(*/.config/google-chrome*)",
    "Bash(*/.config/BraveSoftware*)",
    "Bash(printenv*)",
    "Bash(env)",
    "Read(//**/.ssh/**)",
    "Edit(//**/.ssh/**)",
    "Write(//**/.ssh/**)",
    "Read(//**/*.ppk)",
    "Edit(//**/*.ppk)",
    "Write(//**/*.ppk)",
    "Bash(*.ppk*)",
]


def _read():
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def status():
    """(present, missing): the rules already in the settings file, and the ones that are not."""
    current = set((_read().get("permissions") or {}).get("deny") or [])
    present = [r for r in RULES if r in current]
    missing = [r for r in RULES if r not in current]
    return present, missing


def install():
    """Add every missing rule to the settings file. Everything else in the file is kept.
    Returns the number of rules added."""
    data = _read()
    perms = data.setdefault("permissions", {})
    deny = perms.setdefault("deny", [])
    added = [r for r in RULES if r not in deny]
    deny.extend(added)
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(added)


def state():
    """on, partial or off."""
    present, missing = status()
    if not missing:
        return "on"
    return "partial" if present else "off"
