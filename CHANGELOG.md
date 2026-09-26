# Changelog

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
