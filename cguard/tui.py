"""The settings screen. Arrow keys move, space cycles a rule's mode, right arrow opens the
full description, left arrow returns, s saves, q quits. Standard library only.
"""
import curses
import textwrap

from . import config

HELP_LIST = "up/down move   space cycle mode   right details   p profile   s save   q quit"
HELP_DETAIL = "up/down scroll   space cycle mode   left back   s save   q quit"


def _items():
    out = []
    for group in config.GROUPS:
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
        self.cursor = next(i for i, it in enumerate(self.items) if it[0] == "rule")
        self.view = "list"
        self.scroll = 0
        self.dirty = False
        self.message = ""
        curses.curs_set(0)
        self.colors = False
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_RED, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_GREEN, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            self.colors = True

    def mode_attr(self, mode):
        if not self.colors:
            return curses.A_NORMAL
        return curses.color_pair({"deny": 1, "ask": 2, "off": 3}[mode])

    # ------------------------------------------------------------------ drawing
    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        header = f" cguard settings    profile: {self.cfg['profile']}{'    (unsaved changes)' if self.dirty else ''}"
        self.scr.addnstr(0, 0, header.ljust(w), w - 1, curses.A_REVERSE)
        if self.view == "list":
            self.draw_list(h, w)
            footer = HELP_LIST
        else:
            self.draw_detail(h, w)
            footer = HELP_DETAIL
        self.scr.addnstr(h - 2, 0, (" " + self.message).ljust(w), w - 1, curses.color_pair(4) if self.colors else curses.A_NORMAL)
        self.scr.addnstr(h - 1, 0, (" " + footer).ljust(w), w - 1, curses.A_REVERSE)
        self.scr.refresh()

    def draw_list(self, h, w):
        top = 2
        visible = h - 5
        first = max(0, min(self.cursor - visible // 2, len(self.items) - visible))
        for row, idx in enumerate(range(first, min(len(self.items), first + visible))):
            kind, value = self.items[idx]
            y = top + row
            if kind == "group":
                self.scr.addnstr(y, 1, value, w - 2, curses.A_BOLD)
                continue
            r = config.rule(value)
            mode = self.cfg["rules"][value]
            selected = idx == self.cursor
            prefix = "> " if selected else "  "
            self.scr.addnstr(y, 1, prefix, 2, curses.A_BOLD if selected else curses.A_NORMAL)
            self.scr.addnstr(y, 3, f"[{mode:<4}]", 6, self.mode_attr(mode) | (curses.A_BOLD if selected else 0))
            line = f" {r['title']}  -  {r['short']}"
            self.scr.addnstr(y, 9, line, max(1, w - 10), curses.A_BOLD if selected else curses.A_NORMAL)

    def draw_detail(self, h, w):
        kind, value = self.items[self.cursor]
        r = config.rule(value)
        mode = self.cfg["rules"][value]
        self.scr.addnstr(2, 1, r["title"], w - 2, curses.A_BOLD)
        self.scr.addnstr(3, 1, f"{r['id']}   group: {r['group']}   mode: ", w - 2)
        self.scr.addnstr(3, 1 + len(f"{r['id']}   group: {r['group']}   mode: "), mode, 5, self.mode_attr(mode) | curses.A_BOLD)
        body = []
        for para in (r["short"] + "\n\n" + r["long"]).split("\n\n"):
            body.extend(textwrap.wrap(para, width=max(20, w - 4)) or [""])
            body.append("")
        body.append(f"Modes: deny refuses, ask confirms with you first, off disables this rule.")
        body.append(f"Change it here with space, or from any terminal: cguard set {r['id']} <deny|ask|off>")
        visible = h - 8
        self.scroll = max(0, min(self.scroll, max(0, len(body) - visible)))
        for i, line in enumerate(body[self.scroll:self.scroll + visible]):
            self.scr.addnstr(5 + i, 2, line, w - 3)

    # ------------------------------------------------------------------ actions
    def move(self, delta):
        idx = self.cursor
        while True:
            idx += delta
            if idx < 0 or idx >= len(self.items):
                return
            if self.items[idx][0] == "rule":
                self.cursor = idx
                return

    def cycle_mode(self):
        kind, value = self.items[self.cursor]
        self.cfg["rules"][value] = _cycle(self.cfg["rules"][value])
        self.dirty = True
        self.message = f"{value} = {self.cfg['rules'][value]}"

    def cycle_profile(self):
        names = list(config.PROFILES)
        new = names[(names.index(self.cfg["profile"]) + 1) % len(names)]
        fresh = config.default_config(new)
        fresh["lists"], fresh["audit"] = self.cfg["lists"], self.cfg["audit"]
        self.cfg = fresh
        self.dirty = True
        self.message = f"profile {new}: rule modes reset to its defaults"

    def save(self):
        path = config.save(self.cfg)
        self.dirty = False
        self.message = f"saved to {path}"

    def confirm_quit(self):
        if not self.dirty:
            return True
        h, w = self.scr.getmaxyx()
        self.scr.addnstr(h - 2, 0, " unsaved changes: [s]ave and quit, [d]iscard, or any other key to stay ".ljust(w), w - 1, curses.A_REVERSE)
        self.scr.refresh()
        key = self.scr.getch()
        if key in (ord("s"), ord("S")):
            self.save()
            return True
        if key in (ord("d"), ord("D")):
            return True
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
            elif key in (ord("p"), ord("P")) and self.view == "list":
                self.cycle_profile()
            elif key == ord(" "):
                self.cycle_mode()
            elif self.view == "list":
                if key in (curses.KEY_UP, ord("k")):
                    self.move(-1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    self.move(1)
                elif key in (curses.KEY_RIGHT, curses.KEY_ENTER, 10, 13, ord("l")):
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
