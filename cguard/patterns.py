"""What secret material looks like. Detectors used by every guard.

Two kinds of pattern. Prefixed formats, such as AKIA... or sk-ant-..., cannot occur in
ordinary text, so a match is a match. The generic KEY=value form matches a lot of harmless
configuration, so its value must also pass a placeholder test and an entropy test.

Literals that would make this file match itself are split into adjacent strings.
"""
import math
import os
import re

HEAD_BYTES = 65536          # per file: the whole file for almost every configuration or source file

PREFIXED = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE " r"KEY"), "a private key"),
    (re.compile(r"PuTTY-User-" r"Key-File"), "a PuTTY private key"),
    (re.compile(r"AGE-SECRET-" r"KEY-1"), "an age secret key"),
    (re.compile(r"client-key-" r"data:"), "a kubeconfig with an embedded key"),
    (re.compile(r'"type"\s*:\s*"service_' r'account"'), "a Google Cloud service account key"),
    (re.compile(r"(?<![A-Z0-9])AKIA" r"[0-9A-Z]{16}(?![A-Z0-9])"), "an AWS access key"),
    (re.compile(r"sk-ant-" r"[A-Za-z0-9\-_]{32,}"), "an Anthropic API key"),
    (re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?" r"[A-Za-z0-9_\-]{32,}"), "an OpenAI API key"),
    (re.compile(r"(?<![A-Za-z0-9])hf_" r"[A-Za-z0-9]{34,}"), "a Hugging Face token"),
    (re.compile(r"(?<![A-Za-z0-9])r8_" r"[A-Za-z0-9]{37}"), "a Replicate token"),
    (re.compile(r"(?<![A-Za-z0-9])gh[pousr]_" r"[A-Za-z0-9]{36,}"), "a GitHub token"),
    (re.compile(r"github_pat_" r"[A-Za-z0-9_]{60,}"), "a GitHub fine-grained token"),
    (re.compile(r"(?<![A-Za-z0-9])glpat-" r"[A-Za-z0-9\-_]{20,}"), "a GitLab token"),
    (re.compile(r"(?<![A-Za-z0-9])npm_" r"[A-Za-z0-9]{36}"), "an npm token"),
    (re.compile(r"(?<![A-Za-z0-9])[sr]k_(?:live|test)_" r"[0-9a-zA-Z]{24,}"), "a Stripe key"),
    (re.compile(r"(?<![A-Za-z0-9])sq0(?:atp|csp)-" r"[0-9A-Za-z\-_]{22,}"), "a Square token"),
    (re.compile(r"(?<![A-Za-z0-9])SG\." r"[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "a SendGrid key"),
    (re.compile(r"(?<![A-Za-z0-9])xox[bpasr]-" r"[0-9]{10,13}-[0-9A-Za-z\-]{20,}"), "a Slack token"),
    (re.compile(r"(?<![A-Za-z0-9])[ps]k-lf-" r"[0-9a-f-]{30,}"), "a Langfuse key"),
    (re.compile(r"(?<![A-Za-z0-9])AIza" r"[0-9A-Za-z_\-]{35}"), "a Google API key"),
    (re.compile(r"(?<![A-Za-z0-9])ya29\." r"[0-9A-Za-z_\-]{30,}"), "a Google OAuth token"),
    (re.compile(r"(?<![A-Za-z0-9])dop_v1_" r"[0-9a-f]{64}"), "a DigitalOcean token"),
    (re.compile(r"(?<![A-Za-z0-9])tskey-" r"[A-Za-z0-9\-]{20,}"), "a Tailscale key"),
    (re.compile(r"(?<![A-Za-z0-9])dp\.st\." r"[A-Za-z0-9_\-]{20,}"), "a Doppler token"),
    (re.compile(r"(?<![A-Za-z0-9])pypi-AgEI" r"[A-Za-z0-9_\-]{50,}"), "a PyPI token"),
    (re.compile(r"(?<![A-Za-z0-9])shp(?:at|ss|ca|pa)_" r"[0-9a-fA-F]{32}"), "a Shopify token"),
    (re.compile(r"(?<![A-Za-z0-9])lin_api_" r"[A-Za-z0-9]{40}"), "a Linear API key"),
    (re.compile(r"(?<![A-Za-z0-9])nfp_" r"[A-Za-z0-9]{36,}"), "a Netlify token"),
    (re.compile(r"(?<![A-Za-z0-9])fo1_" r"[A-Za-z0-9_\-]{40,}"), "a Fly.io token"),
    (re.compile(r"(?<![A-Za-z0-9])PMAK-" r"[0-9a-f]{24}-[0-9a-f]{34}"), "a Postman API key"),
    (re.compile(r"(?<![A-Za-z0-9])gsk_" r"[A-Za-z0-9]{40,}"), "a Groq API key"),
    (re.compile(r"(?<![A-Za-z0-9])pplx-" r"[A-Za-z0-9]{40,}"), "a Perplexity API key"),
    (re.compile(r"(?<![A-Za-z0-9])xai-" r"[A-Za-z0-9]{60,}"), "an xAI API key"),
    (re.compile(r"(?<![A-Za-z0-9])dckr_pat_" r"[A-Za-z0-9_\-]{27,}"), "a Docker Hub token"),
    (re.compile(r"(?<![A-Za-z0-9])xapp-1-" r"[A-Z0-9]{9,}-[0-9]{10,}-[a-f0-9]{40,}"), "a Slack app token"),
    (re.compile(r"(?<![0-9])[0-9]{8,10}:AA" r"[A-Za-z0-9_\-]{33}"), "a Telegram bot token"),
    (re.compile(r"discord(?:app)?\.com/api/webhooks/" r"[0-9]{17,20}/[A-Za-z0-9_\-]{60,}"), "a Discord webhook"),
    (re.compile(r"(?<![A-Za-z0-9])SK" r"[0-9a-f]{32}(?![A-Za-z0-9])"), "a Twilio API key"),
    (re.compile(r"(?<![A-Za-z0-9])[0-9a-f]{32}-us" r"[0-9]{1,2}(?![A-Za-z0-9])"), "a Mailchimp API key"),
    (re.compile(r"(?<![A-Za-z0-9])sb(?:p|_secret)_" r"[A-Za-z0-9_\-]{20,}"), "a Supabase key"),
    (re.compile(r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?|amqp)://[^:/\s]+:[^@\s]{4,}@"),
     "a connection string with a password"),
    (re.compile(r"(?i)https?://[^:/\s@]+:[^@/\s]{4,}@[^\s/]+"), "a URL with an embedded password"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_\.=]{30,}"), "a bearer token"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "a JSON web token"),
]

# KEY=value or KEY: value, where the name says secret and the value is long.
GENERIC = re.compile(
    r"(?im)^\s*(?:export\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*"
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)"
    r"[A-Za-z0-9_]*)\s*[=:]\s*['\"]?([^\s'\"#,]{12,})"
)

SECRET_NAME = re.compile(r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)")

PLACEHOLDER = re.compile(
    r"(?i)(?:your[_-]?|example|changeme|change_me|placeholder|dummy|sample|replace|todo|<[^>]+>|\$\{|xxx|"
    r"\.\.\.|^\*+$|^0+$|^1234|password123|_here$|insert|fill_in)|^(.)\1{7,}$"
)

WRITE_PATTERN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE " r"KEY|AGE-SECRET-" r"KEY-1|PuTTY-User-" r"Key-File")


def entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in freq.values())


def is_placeholder(value):
    return bool(PLACEHOLDER.search(value))


def find_secret(text):
    """A label for the first secret-looking thing in text, or None."""
    if not text:
        return None
    for pattern, label in PREFIXED:
        m = pattern.search(text)
        if m and not is_placeholder(m.group(0)):
            return label
    for m in GENERIC.finditer(text):
        value = m.group(2)
        if is_placeholder(value):
            continue
        if entropy(value) >= 3.0:
            return f"credentials in {m.group(1)}=value form"
    return None


def classify_file(path, limit=None):
    """A label if the file at path looks like secret material, else None.

    Reads the first `limit` bytes, HEAD_BYTES by default, so a whole configuration or source
    file and only the head of anything large."""
    limit = HEAD_BYTES if limit is None else max(0, min(limit, HEAD_BYTES))
    try:
        if limit == 0 or not os.path.isfile(path) or os.path.getsize(path) == 0:
            return None
        with open(path, "rb") as f:
            head = f.read(limit)
    except OSError:
        return None
    return find_secret(head.decode("utf-8", errors="replace"))


def mask(s):
    """First and last four characters, the rest stars. For the audit log."""
    if len(s) <= 10:
        return "*" * len(s)
    return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"


def redact(text):
    """Replace every secret-looking span in text with a masked version."""
    out = text
    for pattern, _ in PREFIXED:
        out = pattern.sub(lambda m: mask(m.group(0)), out)
    out = GENERIC.sub(lambda m: m.group(0).replace(m.group(2), mask(m.group(2))), out)
    return out
