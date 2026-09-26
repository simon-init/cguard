# cguard

A Claude Code plugin that keeps secrets, other people's documents and destructive commands
out of an assistant session. Every refusal comes with a way forward.

It is one hook, written in Python with no dependencies, that runs before every Read,
Edit, Write, Grep and Bash call. It reads at most the first 4 KB of a file the tool is
about to touch, and the file content never reaches the model. Only the decision does.

## What it guards

| Rule | Default | What it does |
|---|---|---|
| `secrets.files` | deny | Refuse to read, edit, grep or shell-touch a file whose content looks like a key or credential |
| `secrets.write` | deny | Refuse to write a private key block into any file |
| `secrets.env` | deny | When a variable name says it is a secret, refuse `env`, `printenv` and `echo $NAME` |
| `commit.secrets` | deny | Scan what `git add` and `git commit` are about to record. If a secret is in it, refuse |
| `commit.binaries` | deny | Refuse `git add` of PDFs, office documents, archives, databases and files over 5 MB |
| `commit.add_all` | deny | Refuse `git add -A` and `git add .`. Files are added by name |
| `commit.no_verify` | deny | Refuse `--no-verify` on commit and push |
| `commit.force_push` | ask | Confirm before a force push |
| `commands.fatal` | deny | Refuse `rm -rf` on `/`, `~` or `.`, `mkfs`, `dd` onto a disk, fork bombs |
| `commands.destructive` | ask | Confirm before `git reset --hard`, `git clean -f`, `chmod -R 777`, `docker prune`, `DROP TABLE` and similar |
| `commands.sudo` | ask | Confirm before any command run as root |
| `exfil.pipe_to_shell` | deny | Refuse `curl ... \| sh` and `wget ... \| bash` |
| `exfil.upload` | ask | Confirm before curl uploads, scp, rsync, sftp or nc to a host that is not on the allowlist |
| `self.protect` | deny | Refuse edits to the plugin, its configuration file, Claude Code's own configuration file and the credentials file |
| `paths.boundary` | off | Confirm before touching a file outside the working directory. Ask on the contained profile |
| `packages.install` | off | Confirm before pip, npm, npx, cargo, brew, pacman and apt installs. Ask on the contained profile |
| `session.check` | off | If `.env` is not ignored, or a tracked file holds a secret, warn once per session |

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

Then put the command line on your path, once:

```
ln -s ~/.claude/plugins/marketplaces/cguard/bin/cguard ~/.local/bin/cguard
```

It needs Python 3.11 or later and git. Nothing else is installed.

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
cguard check 'rm -rf build'        dry-run a command
```

The interactive screen, for a person in a terminal:

```
cguard config
```

The keys on that screen:

- Up and down move between rules.
- Enter or space cycles a rule's mode. `d`, `a` and `o` set deny, ask or off directly.
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

## What it cannot see

Say this plainly, because a guard that is trusted beyond what it does is worse than none.

- It reads the first 4 KB of a file. A secret further down passes.
- It reads shell commands as text. A path built by a subshell, an encoded argument, or a
  file read by a program that Claude wrote and then ran, is not seen.
- It knows the formats of common keys and the shape of `KEY=value` lines. A secret that
  looks like ordinary text passes.
- It is a hook inside Claude Code. It does not sandbox anything. A model that is
  determined to misbehave has other routes. The deny list in `settings.json` and a real
  sandbox are the layers below this one.

It is a guardrail for the ordinary case: the accident, the careless command, the file in
the wrong folder. Those are most of the incidents that happen.

## Tests

```
python3 -m unittest discover -s tests -v
```

## Credits

The list of key formats grew out of the secret scanner in ShipSecure, by the same author.
Everything else was written for this plugin.

MIT.
