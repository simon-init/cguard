"""The configuration screen.

Up and down move. Enter or space cycles a rule's mode, or selects a profile; d, a and o
set a rule's mode directly. Right arrow opens the full description, left arrow returns.
s saves, q quits. Standard library only.
"""
import curses
import textwrap

from . import __version__, config

TEXT_WIDTH = 76
HELP_LIST = [("↑↓", "move"), ("enter/space", "cycle mode / select profile"), ("d a o", "deny ask off"),
             ("→", "details"), ("s", "save"), ("q", "quit")]
HELP_DETAIL = [("↑↓", "scroll"), ("enter/space", "cycle mode / select profile"), ("d a o", "deny ask off"),
               ("←", "back"), ("s", "save"), ("q", "quit")]

C_ACCENT, C_DENY, C_ASK, C_OFF, C_DIM, C_SEL = 1, 2, 3, 4, 5, 6


def _items():
    out = [("about", "About cguard"), ("group", "Profile")]
    for name in config.PROFILES:
        out.append(("profile", name))
    for group in config.GROUPS:
        out.append(("blank", ""))
        out.append(("group", group))
        for r in config.RULES:
            if r[1] == group:
                out.append(("rule", r[0]))
    return out


def _cycle(mode):
    modes = list(config.MODES)
    return modes[(modes.index(mode) + 1) % len(modes)]


class Screen:
    def __init__(self, stdscr):
        self.scr = stdscr
        self.cfg = config.load()
        self.items = _items()
        self.cursor = 0
        self.view = "list"
        self.scroll = 0
        self.dirty = False
        self.message = "welcome. every refusal comes with a way forward."
        curses.curs_set(0)
        self.colors = curses.has_colors()
        if self.colors:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(C_ACCENT, curses.COLOR_CYAN, -1)
            curses.init_pair(C_DENY, curses.COLOR_RED, -1)
            curses.init_pair(C_ASK, curses.COLOR_YELLOW, -1)
            curses.init_pair(C_OFF, curses.COLOR_GREEN, -1)
            curses.init_pair(C_DIM, curses.COLOR_WHITE, -1)
            curses.init_pair(C_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)

    def pair(self, n, extra=0):
        return (curses.color_pair(n) if self.colors else 0) | extra

    def mode_attr(self, mode):
        return self.pair({"deny": C_DENY, "ask": C_ASK, "off": C_OFF}[mode], curses.A_BOLD)

    # ------------------------------------------------------------------ drawing
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                self.scr.addnstr(y, x, text, max(0, w - x - 1), attr)
            except curses.error:
                pass

    def header(self, w):
        self.put(0, 0, " " * (w - 1), self.pair(C_SEL))
        self.put(0, 1, "cguard", self.pair(C_SEL, curses.A_BOLD))
        self.put(0, 8, f"v{__version__}", self.pair(C_SEL))
        tag = "guards for a Claude Code session"
        self.put(0, 16, tag, self.pair(C_SEL))
        right = f"profile: {self.cfg['profile']}" + ("   * unsaved" if self.dirty else "")
        self.put(0, max(17 + len(tag), w - len(right) - 2), right, self.pair(C_SEL, curses.A_BOLD))

    def footer(self, h, w, keys):
        self.put(h - 1, 0, " " * (w - 1), curses.A_REVERSE)
        x = 1
        for key, what in keys:
            self.put(h - 1, x, f" {key} ", curses.A_REVERSE | curses.A_BOLD)
            x += len(key) + 3
            self.put(h - 1, x, what, curses.A_REVERSE)
            x += len(what) + 2
        self.put(h - 2, 1, self.message, self.pair(C_ACCENT))

    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        self.header(w)
        if self.view == "list":
            self.draw_list(h, w)
            self.footer(h, w, HELP_LIST)
        else:
            self.draw_detail(h, w)
            self.footer(h, w, HELP_DETAIL)
        self.scr.refresh()

    def draw_list(self, h, w):
        top, visible = 2, h - 5
        first = max(0, min(self.cursor - visible // 2, len(self.items) - visible))
        for row, idx in enumerate(range(first, min(len(self.items), first + visible))):
            kind, value = self.items[idx]
            y = top + row
            selected = idx == self.cursor
            bold = curses.A_BOLD if selected else 0
            if kind == "blank":
                continue
            if kind == "group":
                self.put(y, 2, value.upper(), self.pair(C_ACCENT, curses.A_BOLD))
                self.put(y, 3 + len(value), " " + "─" * max(0, w - len(value) - 6), self.pair(C_DIM))
            elif kind == "about":
                self.put(y, 1, ("▶ " if selected else "  ") + "About cguard", bold)
                self.put(y, 16, "  how it works, what it cannot see, where the log is", self.pair(C_DIM))
            elif kind == "profile":
                active = value == self.cfg["profile"]
                title = config.PROFILE_INFO[value][0]
                self.put(y, 1, "▶ " if selected else "  ", curses.A_BOLD)
                self.put(y, 3, "● " if active else "○ ", self.pair(C_OFF if active else C_DIM, curses.A_BOLD))
                self.put(y, 5, f"{value:<12}", bold | (self.pair(C_ACCENT) if active else 0))
                self.put(y, 18, title, self.pair(C_DIM))
            else:
                r = config.rule(value)
                mode = self.cfg["rules"][value]
                self.put(y, 1, "▶ " if selected else "  ", curses.A_BOLD)
                self.put(y, 3, f"[{mode:<4}]", self.mode_attr(mode))
                self.put(y, 10, r["title"], bold)
                self.put(y, 11 + len(r["title"]), "  " + r["short"], self.pair(C_DIM))

    def body_lines(self, w):
        """[(attr_name, text)] ready to draw, wrapped."""
        kind, value = self.items[self.cursor]
        width = min(TEXT_WIDTH, max(30, w - 6))
        if kind == "about":
            text = config.ABOUT
        elif kind == "profile":
            title, desc = config.PROFILE_INFO[value]
            other = next(n for n in config.PROFILES if n != value)
            diffs = config.profile_differences(value)
            text = desc + f"\n\n## What differs from {other}\n" + "\n".join(f"- {rid}: {mine} here, {theirs} on {other}" for rid, mine, theirs in diffs)
            text += ("\n\nThis profile is active." if value == self.cfg["profile"]
                     else "\n\nPress Enter to select it. Every rule is then reset to this profile's defaults, and your allowlists are kept.")
        else:
            r = config.rule(value)
            text = r["short"] + "\n\n" + r["long"] + f"\n\n## Change it\n- Here: Enter cycles the mode, d a o set it.\n- From any terminal: cguard set {value} <deny|ask|off>"
        lines = []
        for style, item in config.parse_markup(text):
            if style == "blank":
                if lines and lines[-1][1] != "":
                    lines.append(("plain", ""))
            elif style == "header":
                if lines and lines[-1][1] != "":
                    lines.append(("plain", ""))
                lines.append(("header", item))
            elif style == "bullet":
                wrapped = textwrap.wrap(item, width=width - 4) or [""]
                lines.append(("bullet", "• " + wrapped[0]))
                lines.extend(("bullet", "  " + w2) for w2 in wrapped[1:])
            else:
                lines.extend(("plain", w2) for w2 in (textwrap.wrap(item, width=width) or [""]))
        return lines

    def draw_detail(self, h, w):
        kind, value = self.items[self.cursor]
        if kind == "about":
            self.put(2, 3, "About cguard", self.pair(C_ACCENT, curses.A_BOLD))
            self.put(3, 3, "─" * min(TEXT_WIDTH, w - 6), self.pair(C_DIM))
            top = 4
        elif kind == "profile":
            self.put(2, 3, f"Profile: {value}", self.pair(C_ACCENT, curses.A_BOLD))
            self.put(3, 3, config.PROFILE_INFO[value][0], self.pair(C_DIM))
            self.put(4, 3, "─" * min(TEXT_WIDTH, w - 6), self.pair(C_DIM))
            top = 5
        else:
            r = config.rule(value)
            mode = self.cfg["rules"][value]
            self.put(2, 3, r["title"], self.pair(C_ACCENT, curses.A_BOLD))
            meta = f"{r['id']}   {r['group']}   mode "
            self.put(3, 3, meta, self.pair(C_DIM))
            self.put(3, 3 + len(meta), mode, self.mode_attr(mode))
            self.put(4, 3, "─" * min(TEXT_WIDTH, w - 6), self.pair(C_DIM))
            top = 5
        body = self.body_lines(w)
        visible = h - top - 3
        self.scroll = max(0, min(self.scroll, max(0, len(body) - visible)))
        for i, (style, line) in enumerate(body[self.scroll:self.scroll + visible]):
            if style == "header":
                self.put(top + i, 3, line, self.pair(C_ACCENT, curses.A_BOLD))
            elif style == "bullet":
                self.put(top + i, 5, line)
            else:
                self.put(top + i, 3, line)
        if self.scroll + visible < len(body):
            self.put(h - 3, 3, "↓ more", self.pair(C_DIM))
        elif self.scroll > 0:
            self.put(h - 3, 3, "↑ back to the top", self.pair(C_DIM))

    # ------------------------------------------------------------------ actions
    def move(self, delta):
        idx = self.cursor
        while True:
            idx += delta
            if idx < 0 or idx >= len(self.items):
                return
            if self.items[idx][0] not in ("group", "blank"):
                self.cursor = idx
                return

    def activate(self):
        """Enter or space: cycle a rule, select a profile, or open About."""
        kind, value = self.items[self.cursor]
        if kind == "rule":
            self.set_mode()
        elif kind == "profile":
            self.set_profile(value)
        elif kind == "about" and self.view == "list":
            self.view, self.scroll = "detail", 0

    def set_mode(self, mode=None):
        kind, value = self.items[self.cursor]
        if kind != "rule":
            return
        self.cfg["rules"][value] = mode or _cycle(self.cfg["rules"][value])
        self.dirty = True
        self.message = f"{value} = {self.cfg['rules'][value]}   (s to save)"

    def set_profile(self, name):
        if name == self.cfg["profile"]:
            self.message = f"{name} is already the active profile"
            return
        fresh = config.default_config(name)
        fresh["lists"], fresh["audit"] = self.cfg["lists"], self.cfg["audit"]
        self.cfg = fresh
        self.dirty = True
        self.message = f"profile {name}: every rule reset to its defaults, allowlists kept   (s to save)"

    def save(self):
        path = config.save(self.cfg)
        self.dirty = False
        self.message = f"saved to {path}. the next tool call uses it."

    def confirm_quit(self):
        if not self.dirty:
            return True
        h, w = self.scr.getmaxyx()
        self.put(h - 2, 1, "unsaved changes:  s save and quit   d discard and quit   any other key stays", self.pair(C_ASK, curses.A_BOLD))
        self.scr.refresh()
        key = self.scr.getch()
        if key in (ord("s"), ord("S")):
            self.save()
            return True
        if key in (ord("d"), ord("D")):
            return True
        self.message = ""
        return False

    def loop(self):
        while True:
            self.draw()
            key = self.scr.getch()
            if key in (ord("q"), ord("Q")):
                if self.confirm_quit():
                    return
            elif key in (ord("s"), ord("S")):
                self.save()
            elif key in (ord(" "), curses.KEY_ENTER, 10, 13):
                self.activate()
            elif key in (ord("d"), ord("D")):
                self.set_mode("deny")
            elif key in (ord("a"), ord("A")):
                self.set_mode("ask")
            elif key in (ord("o"), ord("O")):
                self.set_mode("off")
            elif self.view == "list":
                if key in (curses.KEY_UP, ord("k")):
                    self.move(-1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    self.move(1)
                elif key in (curses.KEY_RIGHT, ord("l")):
                    self.view, self.scroll = "detail", 0
            else:
                if key in (curses.KEY_UP, ord("k")):
                    self.scroll = max(0, self.scroll - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    self.scroll += 1
                elif key in (curses.KEY_LEFT, 27, ord("h")):
                    self.view = "list"
            if key == curses.KEY_RESIZE:
                self.scr.clear()


def run():
    curses.wrapper(lambda stdscr: Screen(stdscr).loop())
