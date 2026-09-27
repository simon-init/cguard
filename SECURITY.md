# Security policy

cguard is a guard for Claude Code sessions. A weakness in it is a weakness in what it
protects, so reports are welcome and handled with care.

## Report a weakness

A way past a rule, a false sense of safety, or a way for a session to change the guard's
own files or settings: report these privately first. Use GitHub's private reporting on
this repository. Open the **Security** tab and select **Report a vulnerability**. Give the version, the rule, and the smallest command, file or message
that shows the problem, with any real secret replaced by a made-up one.

Expect an answer within seven days. A fix ships as a new version, and the change log
names the problem once the fix is out.

## What is in scope

- A secret, a stray file or a destructive command that a rule promises to stop and does
  not, in the forms the README describes.
- A refusal message or a log line that shows a secret value.
- Any way for a session to turn a rule off, edit the plugin, or change Claude Code's
  settings without the user doing it in a terminal.

## What is not in scope

- The limits the README lists under "What it cannot see". These are known limits, not
  weaknesses. A secret that reads as ordinary words is one. A bare random string with no
  name and no known prefix is another. Content past the first 64 KB of a file is a third.
- Claude Code itself. Report those to Anthropic.

## Supported versions

The newest version only. Every fix goes into the next version, and older versions are
not patched.
