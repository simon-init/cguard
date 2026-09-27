# cguard

![tests](https://github.com/simon-init/cguard/actions/workflows/tests.yml/badge.svg)

A Claude Code plugin that keeps secrets, stray documents and destructive commands
out of an assistant session. Every blocked action comes with a safe alternative.

It is one hook, written in Python with no dependencies, that runs before every Read,
Edit, Write, Grep and Bash call, and on every message you send. It reads the first 64 KB
of a file the tool is about to touch, which is the whole file in almost every case. The
file content never reaches the model. Only the decision does. A message that holds a key
is stopped before it is sent, and Claude Code erases it.

## What it guards

| Rule | Default | What it does |
|---|---|---|
| `secrets.files` | deny | Refuse to read, edit, grep or shell-touch a file whose content looks like a key or credential |
| `secrets.write` | deny | Refuse to write a private key block into any file |
| `secrets.env` | deny | When a variable name says it is a secret, refuse `env`, `printenv` and `echo $NAME` |
| `secrets.prompt` | deny | Stop a message you send that holds a key, pasted logs included, before it reaches the model. Name the line, and say to rotate it |
| `commit.secrets` | deny | Scan what `git add` and `git commit` are about to record. If a secret is in it, refuse |
| `commit.binaries` | deny | Refuse `git add` of PDFs, office documents, archives, databases and files over 5 MB |
| `commit.add_all` | deny | Refuse `git add -A` and `git add .`. Files are added by name |
| `commit.no_verify` | deny | Refuse `--no-verify` on commit and push |
| `commit.force_push` | ask | Confirm before a force push |
| `commands.fatal` | deny | Refuse `rm -rf` on `/`, `~` or `.`, `mkfs`, `dd` onto a disk, fork bombs |
| `commands.destructive` | ask | Confirm before `git reset --hard`, `git clean -f`, `docker prune`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, migration resets, cloud CLI deletes, `docker compose down -v` and similar |
| `commands.sudo` | ask | Confirm before any command run as root |
| `exfil.pipe_to_shell` | deny | Refuse a download piped into an interpreter that would run it, such as `curl ... \| sh`. A pipe into `python3 -c` or `jq` is data and passes |
| `exfil.upload` | ask | Confirm before curl uploads, scp, rsync, sftp or nc to a host that is not on the allowlist |
| `self.protect` | deny | Refuse edits to the plugin, its configuration file, Claude Code's own configuration file and the credentials file |
| `paths.boundary` | off | Confirm before touching a file outside the working directory. Ask on the contained profile |
| `packages.install` | off | Confirm before pip, npm, npx, cargo, brew, pacman and apt installs. Ask on the contained profile |
| `session.check` | off | If `.env` is not ignored, or a tracked file holds a secret, warn once per session |

An `ask` opens Claude Code's own permission dialog, Yes or No, with the reason shown in
it. No ends the tool call, and you type what to do instead. A hook's answer is honoured in every permission
mode. With permission prompts switched off, the dialog still appears. The message check
is the one exception: there, `ask` lets the message through and tells Claude to say that
the key is now in the transcript and must be rotated.

## Known secret paths

The hook finds secrets by content. Claude Code's own configuration can also refuse files
by name, before any hook runs. cguard carries 518 such rules for Linux, macOS and Windows
and installs them into `~/.claude/settings.json` on request, adding only what is missing.
They cover SSH keys, environment files, cloud and password-manager credentials, developer
tool tokens, shell history, browser profiles and keychains. They also cover the commands
whose job is to print a secret. The Windows paths are best effort and untested.

```
cguard denylist status
cguard denylist install
cguard denylist remove
```

Remove is the undo. It takes cguard's rules out and keeps the rest of the file. The same
row exists in the configuration screen, under Files by name, and in `cguard setup`. The
commands and the screens are run by you. Claude cannot edit `settings.json`, and cannot
run install or remove from a shell either, which is the guard's own rule. So the plugin
cannot change the rules on its own. The list is grouped in
`cguard/denylist.py` with one comment per group, so the source is the documentation.

Two profiles. `standard` guards secrets, commits and the machine, and lets Claude move
between folders and install without asking. `contained` adds containment: Claude stays
inside the project, asks before touching anything outside it or installing anything, and
the session check runs. Every rule can be set to `deny`, `ask` or `off` on top of either profile.

## The one rule behind all of them

A guard never says only "no". Every refusal Claude receives has the same shape: what was
blocked, why in one line, how to do it yourself, and how to allow it. For example:

```
cguard deny [commit.binaries]: `git add` of /home/me/app/docs/case.pdf: case.pdf is a .pdf file.
Why: documents and large files in a repository are usually accidents, and history keeps them forever.
Do it yourself: move it out: `mv /home/me/app/docs/case.pdf ~/`  and add the rest by name.
Or allow it: `cguard allow commit_paths docs/case.pdf`
```

Claude relays that to you. You are never left holding a wall.

## Install

In Claude Code, from this repository:

```
claude plugin marketplace add simon-init/cguard
claude plugin install cguard@cguard
```

Then put the command line on your path, once. On Linux and macOS:

```
ln -s ~/.claude/plugins/marketplaces/cguard/bin/cguard ~/.local/bin/cguard
```

On Windows, add this folder to your PATH. The launcher in it is `cguard.cmd`:

```
%USERPROFILE%\.claude\plugins\marketplaces\cguard\bin
```

The hook needs Python 3.9 or later and git. Nothing else is installed. The two screens,
`cguard config` and `cguard setup`, need the curses module. Linux and macOS have it.
Windows Python gets it with `pip install windows-curses`, and every other command works
without it. On Windows, Claude Code runs hooks in Git Bash when Git for Windows is
installed, and the hook needs that. The Windows side follows the documentation and is not
yet tested on a Windows machine. A report is welcome.

## Setup

Once after install, in a terminal:

```
cguard setup
```

A screen with five steps: the profile, the known secret paths, the computers you trust,
the commands worth knowing, and a summary. Up and down move between the answers, and
Enter picks one. Every step waits for you, and the left arrow goes back. Nothing is
written until the last step, except the known secret paths, which are written when you
choose to add them. It is safe to run again. Until the configuration file exists, a
session that starts with the plugin installed gets one line asking Claude to point you
at setup.

## Where the key formats come from

The hook knows two sets of formats. The first set is in `cguard/patterns.py`, written
for this plugin. The second set is imported from the gitleaks rule set, MIT, and lives
in the generated file `cguard/rules_gitleaks.py`. The import keeps only rules with a
fixed prefix. Rules that match a keyword plus any random string are left out on purpose.
In a hook that blocks work, such rules refuse real files. The import script is
`tools/sync_gitleaks.py`. The license notice is in `THIRD_PARTY_LICENSES.md`.

## Changing the configuration

From any terminal, or by asking Claude to run it:

```
cguard show                        what is on, and the allowlists
cguard set commit.add_all ask      change one rule
cguard allow hosts my-server.example.com
cguard allow paths ~/other-project
cguard allow commit_paths fixtures/sample.pdf
cguard profile contained              switch profile
cguard audit                       the last decisions
cguard why                         the last refusal, explained
cguard why list                    the last twenty refusals, numbered; cguard why 3 explains one
cguard check 'rm -rf build'        dry-run a command
```

The interactive screen, for a person in a terminal:

```
cguard config
```

The keys on that screen:

- Up and down move between rules.
- Enter or space cycles a rule's mode. `d` sets deny, `a` sets ask, `o` sets off.
- The right arrow opens the full description, with how the rule works and what it does
  not catch. Up and down scroll it.
- The left arrow returns to the list.
- `p` switches profile. `s` saves and `q` quits.

The first entry, About cguard, explains the mechanism, the detectors and their limits.

Inside a Claude session, `/cguard:config`, `/cguard:audit` and
`/cguard:why` show the same things.

The configuration lives in `~/.claude/cguard.json`. The hook reads the file on
every call, so a change applies to the next tool use without a restart.

## The audit log

Every refusal and every ask is appended to `~/.claude/cguard.log` as one JSON line:
time, tool, rule, mode, what, and the target with any secret masked. It stays on the
machine. To log every shell command as well, turn on `audit.commands` in the
configuration file.

## What it runs, sends and stores

- It runs one Python script, `cguard/hook.py`, before each file and shell tool call, and
  once at session start. Nothing is installed and nothing runs in the background.
- It stores two files under `~/.claude`: `cguard.json`, the configuration, and
  `cguard.log`, the audit log. On your command, `cguard denylist install` adds deny rules
  to `~/.claude/settings.json`, and nothing else touches that file.
- It sends nothing anywhere. The hook makes no network calls. The one script that
  reaches the internet is `tools/sync_gitleaks.py`. A developer runs it by hand to
  refresh the imported key formats from GitHub, and it is not part of the hook.

## What it cannot see

Say this plainly, because a guard that is trusted beyond what it does is worse than none.

- It reads the first 64 KB of a file, and no more than 4 MB per tool call. A secret further
  down in a large file passes.
- It reads shell commands as text. A path built by a subshell, an encoded argument, or a
  file read by a program that Claude wrote and then ran, is not seen.
- It knows the formats of common keys and the shape of `KEY=value` pairs. A secret that
  looks like ordinary text passes. So does a bare random string with no name in front of
  it and no known prefix, in a file or in a message.
- It is a hook inside Claude Code. It does not sandbox anything. A model that is
  determined to misbehave has other routes. The deny list in `settings.json` and a real
  sandbox are the layers below this one.

It is a guardrail for the ordinary case: the accident, the careless command, the file in
the wrong folder. Those are most of the incidents that happen.

## Tests

```
python3 -m unittest discover -s tests -v
```

The unit tests cover the guards without a model, the commit gate included. The `evals/`
folder holds two behaviour cases for Claude Code's plugin evals: a project with a secret
in `.env`, where the key must not reach the reply, and an ordinary configuration file,
which must be read without a refusal. Each case seeds its workspace with a script, so the
run needs the scaffold flag. The runs call the model on your account.

```
claude plugin eval . --scaffold
```

There is no eval case for the commit gate. The eval sandbox masks the git binary as a
credential path, so no run can make a commit, with or without the plugin.

## Privacy

The hook runs on your machine and sends nothing anywhere. [PRIVACY.md](PRIVACY.md) says what
it reads, what it keeps and what it sends, in one page.

## License

MIT.
