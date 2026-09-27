# Privacy

cguard is a hook that runs on your own machine, inside Claude Code. It has no server, no
account and no network access. This page says what it reads, what it keeps and what it
sends, so that the answer to "where does my data go" is short: nowhere.

## What it reads

- The first 64 KB of a file that Claude is about to read, edit, search or touch from a
  shell command, to look for secret material. The content is read by the hook process
  and discarded when the check is done.
- The text of a shell command Claude is about to run.
- The text of a message you send to Claude, before it is sent, to look for a pasted key.
- The staged changes of a commit Claude is about to make.

None of this content reaches the model through the hook. The hook returns a decision,
and only the decision, with a short reason.

## What it keeps

Two files under `~/.claude` on your machine:

- `cguard.json`, the configuration: the profile, the rule modes and your allowlists.
- `cguard.log`, the audit log: one line per refusal or question, with the time, the
  tool, the rule, a short description, and the path or command concerned. Secrets in a
  path or command are masked to their first and last four characters. For a stopped
  message, the log holds the kind of key, never the value.

On your command, `cguard denylist install` adds deny rules to `~/.claude/settings.json`,
and `cguard denylist remove` takes them out again. Nothing else touches that file.

You own both files. Delete them and the plugin forgets everything. There is no copy
anywhere else.

## What it sends

Nothing. The hook makes no network calls. It contacts no service, no telemetry endpoint
and no update server. The one script in the repository that reaches the internet,
`tools/sync_gitleaks.py`, fetches a public rule file from GitHub, is run by hand by a
developer of the plugin, and is not part of the hook.

## Personal data

The hook does not look for personal data and does not store it. A file it scans may
contain personal data, as any file may. The hook reads it only to find secrets and keeps
none of it.

## Changes

This page changes when the plugin's behaviour changes, and the change log names the
version. Questions go to the repository's issues.
