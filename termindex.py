#!/usr/bin/env python3
"""termindex: a tiny, hard-cornered terminal snippet index."""

from __future__ import annotations

import argparse
import curses
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

APP = "termindex"
DEFAULT_DB = Path.home() / ".local/share/termindex/snippets.db"

SEED = [
    ("Check failed systemd units", "systemd", "diagnostics", "systemctl --failed --no-pager", "Quick health check after installing a service.", "systemd,health", "safe"),
    ("Follow Docker service logs", "docker", "debugging", "docker compose logs -f SERVICE", "Follow one Compose service. Replace SERVICE with the service name.", "containers,logs", "safe"),
    ("Find a package owner", "pacman", "packages", "pacman -Qo /path/to/file", "Show which installed package owns a file.", "arch,packages", "safe"),
    ("Inspect listening ports", "networking", "diagnostics", "ss -tulpn", "List TCP/UDP listeners with process names.", "network,ports", "safe"),
    ("Remove unused Docker data", "docker", "cleanup", "docker system prune", "Removes unused containers, networks, images, and build cache.", "containers,cleanup", "dangerous"),
    ("Extract a tar archive", "tar", "files", "tar -xf ARCHIVE.tar -C DESTINATION", "Extract an archive into a chosen destination.", "archive,files", "safe"),
]


@dataclass
class Snippet:
    id: int
    title: str
    tool: str
    category: str
    command: str
    description: str
    tags: str
    safety: str
    created: str
    used: int


def db_path(value: str | None) -> Path:
    return Path(value).expanduser() if value else DEFAULT_DB


class Store:
    FIELDS = ("title", "tool", "category", "command", "description", "tags", "safety")

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.cx = sqlite3.connect(path)
        self.cx.row_factory = sqlite3.Row
        self.cx.executescript("""
            CREATE TABLE IF NOT EXISTS snippets (
              id INTEGER PRIMARY KEY, title TEXT NOT NULL, tool TEXT NOT NULL,
              category TEXT NOT NULL, command TEXT NOT NULL, description TEXT NOT NULL,
              tags TEXT NOT NULL DEFAULT '', safety TEXT NOT NULL DEFAULT 'safe',
              created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, used INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_snippets_usage ON snippets(used DESC, id DESC);
        """)
        if self.count() == 0:
            self.seed()

    def count(self):
        return self.cx.execute("SELECT COUNT(*) FROM snippets").fetchone()[0]

    def seed(self):
        self.cx.executemany("INSERT INTO snippets(title,tool,category,command,description,tags,safety) VALUES(?,?,?,?,?,?,?)", SEED)
        self.cx.commit()

    def all(self, query="") -> list[Snippet]:
        q = f"%{query.strip()}%"
        rows = self.cx.execute("""SELECT * FROM snippets
          WHERE ? = '' OR title LIKE ? OR tool LIKE ? OR category LIKE ? OR command LIKE ? OR description LIKE ? OR tags LIKE ?
          ORDER BY used DESC, id DESC""", (query.strip(), q, q, q, q, q, q)).fetchall()
        return [Snippet(**dict(r)) for r in rows]

    def get(self, sid):
        r = self.cx.execute("SELECT * FROM snippets WHERE id=?", (sid,)).fetchone()
        return Snippet(**dict(r)) if r else None

    def save(self, data, sid=None):
        data = self._clean(data)
        values = tuple(data[k] for k in self.FIELDS)
        if sid:
            self.cx.execute("UPDATE snippets SET title=?,tool=?,category=?,command=?,description=?,tags=?,safety=? WHERE id=?", values + (sid,))
        else:
            self.cx.execute("INSERT INTO snippets(title,tool,category,command,description,tags,safety) VALUES(?,?,?,?,?,?,?)", values)
        self.cx.commit()

    @classmethod
    def _clean(cls, data):
        cleaned = {key: str(data.get(key, "")).strip() for key in cls.FIELDS}
        if not cleaned["title"]: raise ValueError("title is required")
        if not cleaned["command"]: raise ValueError("command is required")
        cleaned["safety"] = "dangerous" if cleaned["safety"].lower().startswith("d") else "safe"
        cleaned["tags"] = ",".join(tag.strip() for tag in cleaned["tags"].split(",") if tag.strip())
        return cleaned

    def delete(self, sid):
        self.cx.execute("DELETE FROM snippets WHERE id=?", (sid,)); self.cx.commit()

    def touch(self, sid):
        self.cx.execute("UPDATE snippets SET used=used+1 WHERE id=?", (sid,)); self.cx.commit()

    def export_json(self, path):
        data = [dict(r) for r in self.cx.execute("SELECT * FROM snippets ORDER BY id").fetchall()]
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, target)

    def import_json(self, path):
        items = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
        if not isinstance(items, list): raise ValueError("JSON root must be a list")
        if not all(isinstance(item, dict) for item in items): raise ValueError("each JSON item must be an object")
        cleaned = [self._clean(item) for item in items]
        with self.cx:
            self.cx.executemany("INSERT INTO snippets(title,tool,category,command,description,tags,safety) VALUES(?,?,?,?,?,?,?)", [tuple(item[k] for k in self.FIELDS) for item in cleaned])

    def close(self):
        self.cx.close()


def copy_text(value):
    for tool, args in (("wl-copy", []), ("xclip", ["-selection", "clipboard"]), ("xsel", ["--clipboard", "--input"])):
        if shutil.which(tool):
            try:
                subprocess.run([tool, *args], input=value, text=True, check=True, timeout=2)
                return tool
            except (OSError, subprocess.SubprocessError):
                pass
    return None


def clip(text):
    return copy_text(text)


class UI:
    def __init__(self, screen, store):
        self.s = screen; self.store = store; self.query = ""; self.rows = []; self.cursor = 0; self.offset = 0; self.toast = ""; self.toast_until = 0
        try: curses.curs_set(0)
        except curses.error: pass
        self.s.keypad(True); self.s.timeout(180)
        try: curses.start_color()
        except curses.error: pass
        try: curses.use_default_colors()
        except curses.error: pass
        # Strict monochrome: bold/standout/dim provide the hierarchy without a
        # terminal theme fighting the interface.
        curses.init_pair(1, curses.COLOR_WHITE, -1); curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE); curses.init_pair(3, curses.COLOR_WHITE, -1); curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_WHITE); curses.init_pair(5, curses.COLOR_WHITE, -1); curses.init_pair(6, curses.COLOR_WHITE, -1); curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_BLACK)

    def toast_msg(self, text): self.toast = text; self.toast_until = time.time() + 2.8
    def add(self, y, x, text, width, attr=0):
        if width <= 0: return
        try: self.s.addnstr(y, x, text, width, attr)
        except curses.error: pass

    def box(self, y, x, h, w, title=""):
        self.add(y, x, "+" + "-" * max(0, w - 2) + "+", w, curses.color_pair(1))
        for row in range(1, h - 1): self.add(y + row, x, "|" + " " * max(0, w - 2) + "|", w, curses.color_pair(1))
        self.add(y + h - 1, x, "+" + "-" * max(0, w - 2) + "+", w, curses.color_pair(1))
        if title: self.add(y, x + 2, f"[ {title} ]", min(w - 4, len(title) + 6), curses.color_pair(3) | curses.A_BOLD)

    def draw(self):
        h, w = self.s.getmaxyx(); self.s.erase()
        if h < 18 or w < 64:
            self.add(1, 2, "termindex needs a 64x18 terminal", w - 4, curses.color_pair(5)); self.s.refresh(); return
        bw, bh = min(w - 2, 108), min(h - 2, 32); x, y = (w - bw) // 2, (h - bh) // 2
        self.rows = self.store.all(self.query)
        self.box(y, x, bh, bw, "TERM/INDEX")
        self.add(y + 1, x + 3, "# SNIPPET VAULT", bw - 6, curses.color_pair(1) | curses.A_BOLD)
        self.add(y + 1, x + bw - 26, f"{len(self.rows):02d} MATCHES  •  LOCAL", 23, curses.color_pair(3))
        self.add(y + 2, x + 2, "" + "=" * (bw - 4), bw - 4, curses.color_pair(3))
        self.add(y + 3, x + 3, "/ " + self.query + ("_" if self.query else "search snippets..."), bw - 6, curses.color_pair(4) if self.query else curses.color_pair(1))
        self.add(y + 4, x + 2, "-" * (bw - 4), bw - 4, curses.color_pair(1))
        list_h = max(5, bh - 13)
        if self.cursor >= len(self.rows): self.cursor = max(0, len(self.rows) - 1)
        if self.cursor < self.offset: self.offset = self.cursor
        if self.cursor >= self.offset + list_h: self.offset = self.cursor - list_h + 1
        for i in range(list_h):
            idx = self.offset + i; yy = y + 5 + i
            if idx >= len(self.rows): break
            sn = self.rows[idx]; selected = idx == self.cursor; marker = ">" if selected else " "
            safety = "!" if sn.safety == "dangerous" else "·"; left = f"{marker} {safety} {sn.title}"
            right = f"{sn.tool} / {sn.category}"
            attr = curses.color_pair(2) if selected else curses.color_pair(1)
            self.add(yy, x + 3, left, bw - 31, attr | (curses.A_BOLD if selected else 0)); self.add(yy, x + bw - 27, right, 23, attr)
        sy = y + 5 + list_h; self.add(sy, x + 2, "-" * (bw - 4), bw - 4, curses.color_pair(1))
        if self.rows:
            sn = self.rows[self.cursor]; self.add(sy + 1, x + 3, f"{sn.tool.upper()}  ·  {sn.category.upper()}  ·  {'DANGER' if sn.safety == 'dangerous' else 'SAFE'}", bw - 6, curses.color_pair(5 if sn.safety == "dangerous" else 3) | curses.A_BOLD)
            self.add(sy + 2, x + 3, sn.command, bw - 6, curses.color_pair(1) | curses.A_BOLD)
            desc = textwrap.wrap(sn.description, max(10, bw - 8))
            self.add(sy + 3, x + 3, desc[0] if desc else "", bw - 6, curses.color_pair(1))
            if sn.tags and sy + 4 < y + bh - 2:
                self.add(sy + 4, x + 3, "# " + sn.tags, bw - 6, curses.color_pair(1) | curses.A_DIM)
        else: self.add(sy + 2, x + 3, "No snippets found. Press n to create one.", bw - 6, curses.color_pair(5))
        footer = " j/k move  / search  n new  e edit  c copy  x run  d delete  i/o I/O  q quit "
        self.add(y + bh - 2, x + 2, footer.center(bw - 4), bw - 4, curses.color_pair(4))
        if self.toast and time.time() < self.toast_until: self.add(y + bh - 3, x + 3, "» " + self.toast, bw - 6, curses.color_pair(5))
        self.s.refresh()

    def prompt(self, label, value="", allow_empty=False):
        h, w = self.s.getmaxyx(); width = min(w - 10, 78); x = (w - width) // 2; y = h // 2
        self.box(y - 2, x, 5, width, label.upper()); self.add(y, x + 3, "> ", 2, curses.color_pair(3)); self.add(y, x + 5, value, width - 8, curses.color_pair(1)); self.s.refresh()
        curses.curs_set(1); curses.echo(); self.s.timeout(-1)
        try: result = self.s.getstr(y, x + 5, width - 8).decode("utf-8", "replace")
        except curses.error: result = value
        curses.noecho()
        try: curses.curs_set(0)
        except curses.error: pass
        self.s.timeout(180)
        result = result.strip()
        return result if (result or allow_empty) else value

    def form(self, existing=None):
        vals = {k: getattr(existing, k, "") for k in ("title", "tool", "category", "command", "description", "tags", "safety")}
        for key, label in (("title", "Title"), ("tool", "Tool"), ("category", "Category"), ("command", "Command"), ("description", "Description"), ("tags", "Tags (comma separated)"), ("safety", "Safety: safe or dangerous")):
            vals[key] = self.prompt(label, vals[key])
        vals["safety"] = "dangerous" if vals["safety"].lower().startswith("d") else "safe"
        return vals

    def save_form(self, existing=None):
        try:
            self.store.save(self.form(existing), existing.id if existing else None)
            self.toast_msg("snippet updated" if existing else "snippet saved")
        except ValueError as error:
            self.toast_msg(str(error))

    def confirm(self, question):
        self.add(0, 0, " " * (self.s.getmaxyx()[1] - 1), self.s.getmaxyx()[1] - 1, curses.color_pair(7)); self.add(0, 2, question + " [y/N]", self.s.getmaxyx()[1] - 4, curses.color_pair(5)); self.s.refresh(); self.s.timeout(-1); c = self.s.getch(); self.s.timeout(180); return c in (ord("y"), ord("Y"))

    def run(self):
        while True:
            self.draw(); c = self.s.getch()
            if c in (ord("q"), 27): return
            if c in (curses.KEY_DOWN, ord("j")): self.cursor += 1
            elif c in (curses.KEY_UP, ord("k")): self.cursor -= 1
            elif c == ord("/"):
                self.query = self.prompt("Search", self.query, allow_empty=True); self.cursor = 0; self.offset = 0
            elif c == ord("n"):
                self.save_form()
            elif c == ord("e") and self.rows:
                self.save_form(self.rows[self.cursor])
            elif c == ord("d") and self.rows:
                sn = self.rows[self.cursor]
                if self.confirm(f"Delete '{sn.title}'?"): self.store.delete(sn.id); self.cursor = max(0, self.cursor - 1); self.toast_msg("snippet deleted")
            elif c == ord("c") and self.rows:
                sn = self.rows[self.cursor]; tool = clip(sn.command); self.store.touch(sn.id); self.toast_msg("copied via " + tool if tool else "clipboard tool not found")
            elif c == ord("x") and self.rows:
                sn = self.rows[self.cursor]
                if self.confirm("Run command? " + sn.command) and (sn.safety != "dangerous" or self.confirm("DANGEROUS command. Run anyway?")):
                    self.store.touch(sn.id); self.s.timeout(-1); self.s.clear(); self.s.refresh(); curses.endwin()
                    try:
                        result = subprocess.run(sn.command, shell=True, check=False)
                        input(f"\n[termindex] exit {result.returncode}; press Enter to return...")
                        self.toast_msg(f"command exited {result.returncode}")
                    finally:
                        self.s = curses.initscr(); self.s.keypad(True); self.s.timeout(180)
            elif c == ord("i"):
                path = self.prompt("Import JSON path");
                try: self.store.import_json(path); self.toast_msg("import complete")
                except Exception as e: self.toast_msg("import failed: " + str(e)[:45])
            elif c == ord("o"):
                path = self.prompt("Export JSON path", "snippets.json")
                try: self.store.export_json(path); self.toast_msg("exported to " + path)
                except Exception as e: self.toast_msg("export failed: " + str(e)[:45])


def main():
    ap = argparse.ArgumentParser(description="compact terminal snippet index")
    ap.add_argument("--db", help="SQLite database path")
    ap.add_argument("--export", metavar="PATH"); ap.add_argument("--import", dest="import_path", metavar="PATH")
    ap.add_argument("--check", action="store_true", help="run a non-interactive health check")
    args = ap.parse_args(); store = Store(db_path(args.db))
    try:
        if args.check:
            assert store.count() >= len(SEED); print(f"ok: {store.count()} snippets in {store.path}"); return 0
        if args.export: store.export_json(args.export); return 0
        if args.import_path: store.import_json(args.import_path); print(f"ok: imported into {store.path}"); return 0
        curses.wrapper(lambda s: UI(s, store).run()); return 0
    finally:
        store.close()


if __name__ == "__main__": sys.exit(main())

