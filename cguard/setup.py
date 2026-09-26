"""The guided setup, as a screen. Run it once after install. It is safe to run again.

Up and down move between the answers, Enter picks one, and every step waits for Enter.
The left arrow goes back a step. Nothing is written until the last step, except the
known secret paths, which are written when you choose to add them.
"""
import curses
import platform
import sys
from pathlib import Path

from . import __version__, config, denylist
from .tui import C_ACCENT, C_ASK, C_DIM, C_OFF, C_SEL, TEXT_WIDTH, _fit, _footer_rows, init_colors, show_cursor, wrap_markup

TAGLINE = "Stay in control of your agent."
LOGO = [
    "                                           _",
    "  ___    __ _   _   _    __ _   _ __    __| |",
    " / __|  / _` | | | | |  / _` | | '__|  / _` |",
    "| (__  | (_| | | |_| | | (_| | | |    | (_| |",
    " \\___|  \\__, |  \\__,_|  \\__,_| |_|     \\__,_|",
    "        |___/",
]
STEPS = ["Welcome", "Profile", "Known secret paths", "Computers you trust", "Commands", "Done"]
HELP = [("↑↓ up/down", "move"), ("enter", "select"), ("← left", "back"), ("q", "quit")]

WELCOME = (
    "cguard is a hook inside Claude Code. It runs before every file and shell command that Claude wants to use. "
    "It refuses, or asks you first, when Claude is about to read a secret, commit a file that does not belong in "
    "git, or run a command that cannot be undone.\n\n"
    "This setup has five steps. You can change every answer later, in `cguard config` or with the cguard commands."
)
PROFILE = (
    "A profile is a set of defaults for all the rules. Pick one. Every rule can still be changed one by one later, "
    "in `cguard config`."
)
COMMANDS = (
    "Five commands you will use. Claude can run the last two for you when you ask.\n\n"
    "- cguard config: the settings screen, every rule with a description.\n"
    "- cguard why: the last refusal, explained, with the way forward.\n"
    "- cguard audit: the last decisions.\n"
    "- cguard set <rule> <deny|ask|off>: change one rule.\n"
    "- cguard allow <paths|hosts|commit_paths> <value>: allow one path, computer or file.\n\n"
    "Inside a Claude session, /cguard:config, /cguard:why and /cguard:audit show the same."
)


def os_name():
    return {"Linux": "Linux", "Darwin": "macOS", "Windows": "Windows"}.get(platform.system(), platform.system())


def short(path):
    """A path with the home folder written as ~, for reading."""
    text, home = str(path), str(Path.home())
    return "~" + text[len(home):] if text.startswith(home) else text


def rules_for_this_os():
    system = platform.system()
    n = 0
    for r in denylist.RULES:
        if "~/Library/" in r or "/Library/" in r:
            n += system == "Darwin"
        elif "AppData" in r:
            n += system == "Windows"
        else:
            n += 1
    return n


class Wizard:
    def __init__(self, stdscr):
        self.scr = stdscr
        self.cfg = config.load()
        self.step = 0
        self.cursor = 0
        self.message = ""
        self.added = None      # rules added to the known secret paths in this run
        self.saved_to = None
        self.repaint = True    # a full repaint on the next draw, set whenever the layout changes
        show_cursor(False)
        self.colors = init_colors()

    def pair(self, n, extra=0):
        return (curses.color_pair(n) if self.colors else 0) | extra

    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and 0 <= x < w - 1 and text:
            try:
                self.scr.addnstr(y, x, text, max(0, w - x - 1), attr)
            except curses.error:
                pass

    # ------------------------------------------------------------------ content
    def hosts(self):
        return self.cfg["lists"]["hosts"]

    def counts(self):
        modes = self.cfg["rules"].values()
        return sum(m == "deny" for m in modes), sum(m == "ask" for m in modes), sum(m == "off" for m in modes)

    def content(self):
        """(body markup, [(label, hint, action)]) for the current step."""
        if self.step == 0:
            return WELCOME, [("Start", "", self.next), ("Quit", "", self.quit)]
        if self.step == 1:
            options = [(name, config.PROFILE_INFO[name][0], lambda n=name: self.pick_profile(n)) for name in config.PROFILES]
            return PROFILE, options
        if self.step == 2:
            present, missing = denylist.status()
            text = (f"Claude Code has its own permission list, in {short(denylist.SETTINGS_PATH)}. A rule there refuses a file by "
                    f"its name, before any hook runs. cguard comes with {len(denylist.RULES)} such rules: SSH keys, .env "
                    "files, cloud and password-manager credentials, shell history, browser profiles, keychains, and the "
                    "commands that print a secret.\n\n"
                    f"This is {os_name()}. {rules_for_this_os()} of the rules apply here. The rest are for the other "
                    "systems, never match, and cost nothing.")
            if self.added is not None:
                text += f"\n\n## On this machine\nAdded {self.added}. Claude Code loads them when a session starts."
                return text, [("Continue", "", self.next)]
            if not missing:
                text += f"\n\n## On this machine\nAll {len(denylist.RULES)} rules are already in place."
                return text, [("Continue", "", self.next)]
            text += f"\n\n## On this machine\n{len(present)} of {len(denylist.RULES)} rules are in place, {len(missing)} are missing."
            return text, [(f"Add the {len(missing)} missing rules", f"writes to {short(denylist.SETTINGS_PATH)} now", self.add_rules),
                          ("Skip for now", "later: cguard denylist install", self.next)]
        if self.step == 3:
            text = ("Sometimes Claude copies a file to another computer, for example with scp, rsync or a curl upload. "
                    "cguard asks you before every such copy, because that is how a file leaves this machine.\n\n"
                    "If there is a computer you send files to on purpose, such as your own server, add it here. Copies "
                    "to that computer then run without a question. Use the name or the address as you type it in the "
                    "command, for example my-server.example.com or 10.0.0.5.\n\n"
                    "## Trusted now\n" + (", ".join(self.hosts()) if self.hosts() else "none"))
            options = [("Continue", "", self.next), ("Add a computer", "", self.add_host)]
            options += [(f"Remove {h}", "", lambda h=h: self.remove_host(h)) for h in self.hosts()]
            return text, options
        if self.step == 4:
            return COMMANDS, [("Continue", "", self.next)]
        deny, ask, off = self.counts()
        text = (f"## Saved\n- configuration: {short(self.saved_to)}\n- log: {short(config.AUDIT_PATH)}\n"
                f"- profile: {self.cfg['profile']}, {deny} rules deny, {ask} ask, {off} off\n"
                f"- computers you trust: {', '.join(self.hosts()) if self.hosts() else 'none'}\n\n"
                "## From now on\n"
                "Restart every Claude Code session that is open now. A session loads the plugin and the known secret "
                "paths when it starts. The rules in the configuration file apply from the next tool call.\n\n"
                "Change anything later in `cguard config`, or run `cguard setup` again.")
        return text, [("Finish", "", self.quit)]

    # ------------------------------------------------------------------ actions
    def next(self):
        self.step += 1
        self.cursor = 0
        self.message = ""
        self.repaint = True
        if self.step == 1:
            self.cursor = list(config.PROFILES).index(self.cfg["profile"])
        if self.step == len(STEPS) - 1:
            self.saved_to = config.save(self.cfg)

    def back(self):
        if 0 < self.step < len(STEPS) - 1:
            self.step -= 1
            self.cursor = 0
            self.message = ""
            self.repaint = True

    def quit(self):
        return "quit"

    def pick_profile(self, name):
        if name != self.cfg["profile"]:
            fresh = config.default_config(name)
            fresh["lists"], fresh["audit"] = self.cfg["lists"], self.cfg["audit"]
            self.cfg = fresh
        self.next()

    def add_rules(self):
        self.added = denylist.install()
        self.cursor = 0
        self.repaint = True

    def add_host(self):
        value = self.read_line("Name or address of the computer: ").strip()
        if value:
            config.add_to_list(self.cfg, "hosts", value)
            self.message = f"added {value}"
        self.cursor = 0
        self.repaint = True

    def remove_host(self, host):
        config.remove_from_list(self.cfg, "hosts", host)
        self.message = f"removed {host}"
        self.cursor = 0
        self.repaint = True

    def read_line(self, prompt):
        h, w = self.scr.getmaxyx()
        y = h - len(_footer_rows(HELP, w)) - 1
        self.put(y, 0, " " * (w - 1))
        self.put(y, 1, prompt, self.pair(C_ASK, curses.A_BOLD))
        self.scr.refresh()
        curses.echo()
        show_cursor(True)
        try:
            raw = self.scr.getstr(y, 1 + len(prompt), max(1, w - len(prompt) - 3))
        except curses.error:
            raw = b""
        finally:
            curses.noecho()
            show_cursor(False)
        return raw.decode("utf-8", "ignore")

    def confirm_quit(self):
        if self.step in (0, len(STEPS) - 1):
            return True
        h, w = self.scr.getmaxyx()
        y = h - len(_footer_rows(HELP, w)) - 1
        note = "leave setup? nothing is saved yet." + ("  the known secret paths stay added." if self.added else "")
        self.put(y, 0, " " * (w - 1))
        self.put(y, 1, _fit(note + "  y yes, press any other key to stay", w - 2), self.pair(C_ASK, curses.A_BOLD))
        self.scr.refresh()
        if self.scr.getch() in (ord("y"), ord("Y")):
            return True
        self.message = ""
        return False

    # ------------------------------------------------------------------ drawing
    def header(self, w):
        self.put(0, 0, " " * (w - 1), self.pair(C_SEL))
        self.put(0, 1, "cguard", self.pair(C_SEL, curses.A_BOLD))
        self.put(0, 8, f"v{__version__}", self.pair(C_SEL))
        self.put(0, 16, "setup", self.pair(C_SEL))
        if self.step > 0:
            right = f"step {self.step} of {len(STEPS) - 1}"
            self.put(0, max(22, w - len(right) - 2), right, self.pair(C_SEL, curses.A_BOLD))

    def footer(self, h, w):
        rows = _footer_rows(HELP, w)
        for i, row in enumerate(rows):
            y = h - len(rows) + i
            self.put(y, 0, " " * (w - 1), curses.A_REVERSE)
            x = 1
            for key, meaning in row:
                self.put(y, x, key, curses.A_REVERSE | curses.A_BOLD)
                x += len(key)
                self.put(y, x, meaning, curses.A_REVERSE)
                x += len(meaning)
        self.put(h - len(rows) - 1, 1, _fit(self.message, w - 2), self.pair(C_ACCENT))

    def draw(self):
        self.scr.erase()
        if self.repaint:
            self.scr.clearok(True)
            self.repaint = False
        h, w = self.scr.getmaxyx()
        self.header(w)
        width = min(TEXT_WIDTH, max(24, w - 6))
        y = 2
        if self.step == 0:
            if w >= 52 and h >= 22:
                for line in LOGO:
                    self.put(y, 3, line, self.pair(C_ACCENT, curses.A_BOLD))
                    y += 1
            else:
                self.put(y, 3, "cguard", self.pair(C_ACCENT, curses.A_BOLD))
                y += 1
            self.put(y, 3, _fit(TAGLINE, w - 4), curses.A_BOLD)
            y += 2
        else:
            self.put(y, 3, _fit(STEPS[self.step], w - 4), self.pair(C_ACCENT, curses.A_BOLD))
            self.put(y + 1, 3, "─" * width, self.pair(C_DIM))
            y += 2
        body, options = self.content()
        for style, line in wrap_markup(body, width):
            if style == "header":
                self.put(y, 3, line, self.pair(C_ACCENT, curses.A_BOLD))
            elif style == "bullet":
                self.put(y, 5, line)
            else:
                self.put(y, 3, line)
            y += 1
        y += 1
        self.cursor = max(0, min(self.cursor, len(options) - 1))
        for i, (label, hint, _) in enumerate(options):
            selected = i == self.cursor
            self.put(y, 1, "▶ " if selected else "  ", curses.A_BOLD)
            x = 3
            if self.step == 1:
                active = label == self.cfg["profile"]
                self.put(y, x, "● " if active else "○ ", self.pair(C_OFF if active else C_DIM, curses.A_BOLD))
                x += 2
            self.put(y, x, _fit(label, w - x - 1), self.pair(C_ACCENT, curses.A_BOLD) if selected else curses.A_BOLD)
            x += len(label) + 2
            if hint:
                self.put(y, x, _fit(hint, w - x - 1), self.pair(C_DIM))
            y += 1
        self.footer(h, w)
        self.scr.refresh()

    def loop(self):
        while True:
            self.draw()
            key = self.scr.getch()
            if key == curses.KEY_RESIZE:
                self.scr.clear()
            elif key in (ord("q"), ord("Q")):
                if self.confirm_quit():
                    return
            elif key in (curses.KEY_UP, ord("k")):
                self.cursor -= 1
            elif key in (curses.KEY_DOWN, ord("j")):
                self.cursor += 1
            elif key in (curses.KEY_LEFT, curses.KEY_BACKSPACE, 127, 8, ord("h")):
                self.back()
            elif key in (curses.KEY_ENTER, 10, 13, ord(" ")):
                _, options = self.content()
                self.cursor = max(0, min(self.cursor, len(options) - 1))
                if options[self.cursor][2]() == "quit":
                    return


def run():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("cguard setup is a screen and needs a terminal. Open one and run: cguard setup")
        return 2
    curses.wrapper(lambda stdscr: Wizard(stdscr).loop())
    return 0
