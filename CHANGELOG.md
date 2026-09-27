# Changelog

## 0.1.48, 2026-09-27

The privacy page in plainer sentences.

## 0.1.47, 2026-09-27

A privacy page, PRIVACY.md, linked from the README and named in the manifest as privacyPolicyUrl. It says what the hook reads, what it keeps and what it sends, which is nothing.

## 0.1.46, 2026-09-27

The texts describe the permission dialog as it is: Yes or No, with the reason shown, and No ends the tool call so you can type what to do instead. There is no third button.

## 0.1.45, 2026-09-27

A test workflow on GitHub Actions runs the unit tests on every push, on Linux with Python 3.9 and 3.12 and on macOS with 3.12, with a badge in the README. The README's opening paragraph covers the message check, the note on ask says what it means for that rule, and the list of what the guard cannot see names the bare random string.

## 0.1.44, 2026-09-27

When the secret sits inside a pasted block, the guard counts the line from the block's first line and says "of the pasted text", because Claude Code wraps a paste and adds lines in front of it that the user never sees.

## 0.1.43, 2026-09-27

The message block is stated in both places the hook documentation describes, at the top level of the JSON and inside hookSpecificOutput, so it holds whichever form Claude Code reads.

## 0.1.42, 2026-09-27

The message block did not block. The hook signalled it with exit code 2, and the manifest runs `python3 ... || python ...` for Windows, so the non-zero exit started the fallback, which found no input and exited 0, and Claude Code let the message through. The block now travels as a JSON decision on standard output with exit 0, the same way the permission decisions do. Found by pasting a test line after a restart.

## 0.1.41, 2026-09-27

The icon's C is centred again. The three stripes behind it step down and grow: the top one shortest, the bottom one longest and set lower, all fading towards their tails.

## 0.1.40, 2026-09-27

The icon has three speed stripes behind the C, fading towards the tail, so the C reads as moving to the right. The drawing sits a little further right to keep the whole centred.

## 0.1.39, 2026-09-27

The NAME=value detector finds a pair anywhere in a line, not only at its start: a token in a query string, a JSON field or a request header such as X-Api-Key, which is how secrets sit in pasted logs. The name may be quoted and may use hyphens. When a message is stopped, the guard names the line the secret is on. The icon is Simon's drawing on a square canvas with a soft green background.

## 0.1.38, 2026-09-27

The NAME=value detector now matches a name that is exactly the keyword: API_KEY=, TOKEN=, SECRET=, PASSWORD= and their lower-case forms. Before, it needed at least one character in front of the keyword, so DB_PASSWORD= was caught and API_KEY= was not, in files and in messages alike. The descriptions of the file rule and the message rule now say that a bare random string with no name and no known prefix is not caught.

## 0.1.37, 2026-09-27

A new rule, secrets.prompt, on by default. When a message you send holds a key, the hook stops it before it reaches the model. Claude Code erases it, and you see one line that names the kind of key, says nothing left the machine, and says to rotate the key if it was pasted anywhere else. In ask mode the message goes through and Claude is told to say the key must be rotated. Eighteen rules.

## 0.1.36, 2026-09-27

The description line is "Every blocked action comes with a safe alternative." The same words replace "way forward" in the manifests, the README, the welcome line of the settings screen, the setup screen, the why command and the rule descriptions, where the section is now called Safe alternative.

## 0.1.35, 2026-09-27

An icon for the directory listing. The eval fixtures no longer place a web address beside a fake key, which the directory's scanner read as a credential sent to a host.

## 0.1.34, 2026-09-26

The README says what the plugin runs, sends and stores: one Python hook, two files under ~/.claude, no network calls.

## 0.1.33, 2026-09-26

The pipe rule refuses a download only when the receiving command would run it: a shell or interpreter with no script of its own, directly or through sudo. A pipe into python3 -c, python3 -m json.tool, perl -ne, node -e, jq or a script file reads the download as data and passes. bash -c "$(curl ...)" and bash <(curl ...) are refused as well. The test file no longer holds a complete fake key, so the guard does not refuse to read it. cguard set self.protect off or ask from inside a session is refused, and setting it back to deny stays allowed.

## 0.1.32, 2026-09-26

The commit-gate eval case is removed. Claude Code's eval sandbox masks the git binary as a credential path, so no run can make a commit, with or without the plugin, and a case that cannot pass says nothing. The commit gate keeps its unit tests.

## 0.1.31, 2026-09-26

The shell rules for environment files in the known secret paths were too wide. A command with grep somewhere and .env anywhere later was refused, which hit a search for process.env and a commit message that names .env. They now require the file name as an argument, preceded by a space or a slash, and they cover .env.local and the like. Eight rules become 66, 518 in all. cguard denylist install and remove take the old eight out.

## 0.1.29, 2026-09-26

A redirect elsewhere in a command, such as 2>/dev/null, no longer counts as a write to a protected file. Only a redirect or tee aimed at the file counts, next to the explicit write commands. A third eval case, commit-everything, for the commit gate: the first commit of a project with a secret in .env, where the secret must stay out of the commit.

## 0.1.28, 2026-09-26

An eval suite of two cases under evals/, for claude plugin eval: a project with a secret in .env, where the key must not reach the reply, and an ordinary configuration file, which must be read without a refusal.

## 0.1.27, 2026-09-26

The command line runs on macOS and Windows. The launcher resolves its own symlink without readlink -f, uses python when python3 is not found, and a cguard.cmd launcher is added for Windows. When the curses module is missing, the two screens say so and name the package to install, instead of crashing. The hook runs on Python 3.9, so the macOS system Python is enough. rm -rf / is reported as the fatal command it is, even when the plugin folder lies in its path. The marketplace has a description.

## 0.1.26, 2026-09-26

cguard denylist remove takes cguard's rules out of Claude Code's settings file and keeps everything else, the undo for install. The self-protect rule now also refuses cguard denylist install and remove when Claude runs them from a shell. The known secret paths are changed by you in a terminal, never from inside a session.

## 0.1.25, 2026-09-26

The wordmark on the setup screen starts right under the header bar.

## 0.1.24, 2026-09-26

A row of space under the wordmark, the tagline "Move fast, stay in control.", and the known secret paths step names the settings file in every state.

## 0.1.23, 2026-09-26

cguard setup is a screen with the look of the configuration screen. Up and down move between the answers, Enter picks one, the left arrow goes back, and every step waits. A text wordmark on the welcome screen. Plainer words on the trusted computers step, and the last step says to restart open sessions. The screens no longer crash on a terminal that cannot hide the cursor, and wrapped text no longer breaks at hyphens.

## 0.1.22, 2026-09-26

106 fixed-prefix key formats imported from the gitleaks rule set (MIT), generated by tools/sync_gitleaks.py, checked after cguard's own 44 and masked in the log. A first cguard setup, in plain prompts. The destructive-commands rule also asks before terraform destroy, kubectl delete, helm uninstall, migration resets, docker compose down -v, cloud CLI deletes, dropdb and redis flush.

## 0.1.21, 2026-09-26

The selected row is coloured rather than highlighted, and About has a row of space below it.

## 0.1.20, 2026-09-26

Known secret paths grows from 140 to 460 rules: developer tool tokens, commands that print a secret, more history files, keychains, browsers and messaging apps on macOS and Linux, and best-effort Windows paths.

## 0.1.19, 2026-09-26

Known secret paths: the plugin carries the 140 deny rules for Claude Code's own permissions and installs the missing ones on request, from the screen or with `cguard denylist install`. The quit prompt says to press any other key to stay.

## 0.1.18, 2026-09-26

The screen adapts to the terminal width: every row leads with its name in bold, descriptions are cut with an ellipsis, the footer wraps onto two rows, and the header drops its tagline when narrow.

## 0.1.16, 2026-09-26

Arrow glyphs beside the words in the footer.

## 0.1.15, 2026-09-26

The footer and the scroll hints use words instead of arrow glyphs.

## 0.1.14, 2026-09-26

The footer pairs each key with its meaning.

## 0.1.13, 2026-09-26

`cguard why n` explains the n-th most recent refusal, `cguard why list` numbers the last twenty.

## 0.1.12, 2026-09-26

The hook reads the first 64 KB of a file instead of 4 KB, the whole file in almost every case, with a 4 MB budget per tool call. The About text says where the configuration and the log are and how to read them.

## 0.1.11, 2026-09-26

Room at the bottom of the description and list views.

## 0.1.10, 2026-09-26

Every description is structured: headers for how it works, why it exists, what it does not catch and the way forward, with bullets for lists. The settings screen and `cguard explain` render them.

## 0.1.9, 2026-09-26

The boundary rule is described by scope: a session stays inside the project it was opened in.

## 0.1.8, 2026-09-26

Wording.

## 0.1.7, 2026-09-26

Twenty-one more key formats with a fixed prefix, 44 in all: Google, DigitalOcean, Tailscale, Doppler, PyPI, Shopify, Linear, Netlify, Fly, Postman, Groq, Perplexity, xAI, Docker Hub, Slack app, Telegram, Discord webhooks, Twilio, Mailchimp, Supabase.

## 0.1.6, 2026-09-26

The descriptions name no other product.

## 0.1.5, 2026-09-26

The About text and the README say what an ask does: it opens Claude Code's permission dialog, even with permission prompts switched off.

## 0.1.4, 2026-09-26

An empty row between the sections of the settings screen.

## 0.1.3, 2026-09-26

Profiles are `standard` and `contained`, named for how far Claude may move. The About text states the token cost of a refusal and an ask accurately.

## 0.1.2, 2026-09-26

Profiles have descriptions. The settings screen lists them, shows which is active and what differs, and selects one with Enter. `cguard profiles` prints the same. Author fields use the GitHub name.

## 0.1.1, 2026-09-26

The settings screen: Enter cycles the mode, d, a and o set it, text wraps at 76 columns, an About entry, and every description now says how the rule works and what it does not catch.

## 0.1.0, 2026-09-26

First version. Seventeen rules in six groups, two profiles, a command line, an interactive
settings screen, an audit log, and a test set.
