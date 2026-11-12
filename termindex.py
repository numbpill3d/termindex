#!/usr/bin/env python3
"""termindex: a tiny, hard-cornered terminal snippet index."""

from __future__ import annotations

import argparse
import base64
import curses
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path

APP = "termindex"
DEFAULT_DB = Path.home() / ".local/share/termindex/snippets.db"
DEFAULT_SETTINGS = Path.home() / ".config/termindex/settings.json"
ONION_SECRET_HEADER = b"== ed25519v1-secret: type0 ==\x00\x00\x00"
ONION_PUBLIC_HEADER = b"== ed25519v1-public: type0 ==\x00\x00\x00"
ONION_PREFIX = re.compile(r"^[a-z2-7]*$")

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


@dataclass
class Settings:
    startup_animation: bool = True
    show_descriptions: bool = True

    @classmethod
    def load(cls, path: Path = DEFAULT_SETTINGS):
        try:
            raw = json.loads(path.expanduser().read_text(encoding="utf-8"))
            if not isinstance(raw, dict): raise ValueError("settings must be an object")
            startup_animation = raw.get("startup_animation", True)
            show_descriptions = raw.get("show_descriptions", True)
            return cls(
                startup_animation=startup_animation if isinstance(startup_animation, bool) else True,
                show_descriptions=show_descriptions if isinstance(show_descriptions, bool) else True,
            )
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            return cls()

    def save(self, path: Path = DEFAULT_SETTINGS):
        target = path.expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps({
            "startup_animation": self.startup_animation,
            "show_descriptions": self.show_descriptions,
        }, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, target)


@dataclass
class OnionMaterial:
    address: str
    seed: bytes
    public_key: bytes
    attempts: int
    elapsed: float


class OnionGenerationCancelled(Exception):
    pass


def onion_address(public_key: bytes) -> str:
    """Encode a Tor v3 onion address from its 32-byte Ed25519 public key."""
    if len(public_key) != 32: raise ValueError("Ed25519 public key must be 32 bytes")
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode("ascii").lower() + ".onion"


def generate_onion(prefix="", progress=None) -> OnionMaterial:
    """Generate a v3 identity using OpenSSL, optionally searching a vanity prefix."""
    prefix = prefix.lower().strip()
    if not ONION_PREFIX.fullmatch(prefix): raise ValueError("prefix must use a-z and 2-7 only")
    if len(prefix) > 2: raise ValueError("prefix is limited to 2 characters")
    if not shutil.which("openssl"): raise RuntimeError("openssl is required for onion identity generation")
    started = time.monotonic(); attempts = 0
    with tempfile.TemporaryDirectory(prefix="termindex-onion-") as work:
        key_der = Path(work) / "key.der"; public_der = Path(work) / "public.der"
        while attempts < 10_000:
            attempts += 1
            try:
                subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-outform", "DER", "-out", str(key_der)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
                subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(key_der), "-pubout", "-outform", "DER", "-out", str(public_der)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
            except (OSError, subprocess.SubprocessError) as error:
                raise RuntimeError("OpenSSL could not generate an Ed25519 key") from error
            private_der = key_der.read_bytes(); public_der_bytes = public_der.read_bytes()
            seed, public_key = private_der[-32:], public_der_bytes[-32:]
            address = onion_address(public_key)
            if progress and (attempts == 1 or attempts % 8 == 0 or address[0:-6].startswith(prefix)):
                progress(attempts, time.monotonic() - started)
            if address[:-6].startswith(prefix):
                return OnionMaterial(address, seed, public_key, attempts, time.monotonic() - started)
        raise TimeoutError("no matching onion address found within 10,000 attempts")


def save_onion_material(material: OnionMaterial, directory: str | Path) -> Path:
    target = Path(directory).expanduser()
    if target.exists() and any(target.iterdir()): raise FileExistsError("output directory is not empty")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target, 0o700)
    expanded = bytearray(hashlib.sha512(material.seed).digest())
    expanded[0] &= 248
    expanded[31] &= 63
    expanded[31] |= 64
    files = {
        "hostname": (material.address + "\n").encode(),
        "hs_ed25519_public_key": ONION_PUBLIC_HEADER + material.public_key,
        "hs_ed25519_secret_key": ONION_SECRET_HEADER + bytes(expanded),
    }
    for name, contents in files.items():
        destination = target / name
        with tempfile.NamedTemporaryFile(dir=target, prefix=f".{name}.", delete=False) as temporary:
            temporary.write(contents); temporary.flush(); os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, destination)
    return target


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
        if sid is not None:
            self.cx.execute("UPDATE snippets SET title=?,tool=?,category=?,command=?,description=?,tags=?,safety=? WHERE id=?", values + (sid,))
        else:
            self.cx.execute("INSERT INTO snippets(title,tool,category,command,description,tags,safety) VALUES(?,?,?,?,?,?,?)", values)
        self.cx.commit()

    @classmethod
    def _clean(cls, data):
        cleaned = {key: ("" if data.get(key, "") is None else str(data.get(key, "")).strip()) for key in cls.FIELDS}
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


def copy_snippet(store, snippet):
    tool = clip(snippet.command)
    if tool:
        store.touch(snippet.id)
    return tool


class UI:
    def __init__(self, screen, store, settings=None):
        self.s = screen; self.store = store; self.settings = settings or Settings(); self.query = ""; self.rows = []; self.cursor = 0; self.offset = 0; self.toast = ""; self.toast_until = 0
        self.setup_terminal()

    def setup_terminal(self):
        self.s.keypad(True); self.s.timeout(180)
        try: curses.curs_set(0)
        except curses.error: pass
        try: curses.start_color(); curses.use_default_colors()
        except curses.error: pass
        # Keep the palette small so it remains legible across terminal themes.
        for pair, fg, bg in ((1, curses.COLOR_WHITE, -1), (2, curses.COLOR_BLACK, curses.COLOR_WHITE), (3, curses.COLOR_CYAN, -1), (4, curses.COLOR_BLACK, curses.COLOR_CYAN), (5, curses.COLOR_YELLOW, -1), (6, curses.COLOR_RED, -1), (7, curses.COLOR_WHITE, curses.COLOR_BLACK)):
            try: curses.init_pair(pair, fg, bg)
            except curses.error: pass

    def toast_msg(self, text): self.toast = text; self.toast_until = time.time() + 2.8
    def add(self, y, x, text, width, attr=0):
        if width <= 0: return
        try: self.s.addnstr(y, x, text, width, attr)
        except curses.error: pass

    def box(self, y, x, h, w, title="", attr=None):
        attr = curses.color_pair(1) if attr is None else attr
        self.add(y, x, "┌" + "─" * max(0, w - 2) + "┐", w, attr)
        for row in range(1, h - 1): self.add(y + row, x, "│" + " " * max(0, w - 2) + "│", w, attr)
        self.add(y + h - 1, x, "└" + "─" * max(0, w - 2) + "┘", w, attr)
        if title and w > 8: self.add(y, x + 2, f" {title} ", min(w - 4, len(title) + 2), curses.color_pair(3) | curses.A_BOLD)

    def draw(self):
        h, w = self.s.getmaxyx(); self.s.erase()
        if h < 18 or w < 64:
            self.add(1, 2, f"termindex needs a 64×18 terminal (current: {w}×{h})", max(1, w - 4), curses.color_pair(5)); self.s.refresh(); return
        self.rows = self.store.all(self.query)
        if w < 88 or h < 24:
            self.draw_compact(h, w)
            return
        bw, bh = min(w - 4, 120), min(h - 4, 38); x, y = (w - bw) // 2, (h - bh) // 2
        self.box(y, x, bh, bw, "TERM/INDEX")
        self.add(y + 1, x + 3, "SNIPPET VAULT", bw - 32, curses.color_pair(1) | curses.A_BOLD)
        self.add(y + 1, x + bw - 28, f"{len(self.rows):02d} MATCHES  ·  LOCAL", 25, curses.color_pair(3))
        self.add(y + 2, x + 2, "─" * (bw - 4), bw - 4, curses.color_pair(3))
        self.add(y + 3, x + 3, "/ " + (self.query or "search title, command, tag..."), bw - 6, curses.color_pair(4) if self.query else curses.color_pair(1) | curses.A_DIM)
        self.add(y + 4, x + 2, "─" * (bw - 4), bw - 4, curses.color_pair(1))
        list_h = max(5, bh - 12)
        self.cursor = max(0, min(self.cursor, max(0, len(self.rows) - 1)))
        if self.cursor < self.offset: self.offset = self.cursor
        if self.cursor >= self.offset + list_h: self.offset = self.cursor - list_h + 1
        list_w = max(28, int((bw - 5) * 0.48)); detail_x = x + 3 + list_w + 2
        self.add(y + 5, detail_x, "DETAIL", bw - (detail_x - x) - 3, curses.color_pair(3) | curses.A_BOLD)
        for i in range(list_h):
            idx = self.offset + i; yy = y + 5 + i
            if idx >= len(self.rows): break
            sn = self.rows[idx]; selected = idx == self.cursor; marker = "▸" if selected else " "
            safety = "!" if sn.safety == "dangerous" else "·"; left = f"{marker} {safety} {sn.title}"
            attr = curses.color_pair(2) if selected else curses.color_pair(1)
            self.add(yy, x + 3, left, list_w, attr | (curses.A_BOLD if selected else 0))
        self.add(y + 5 + list_h, x + 2, "─" * (bw - 4), bw - 4, curses.color_pair(1))
        if self.rows:
            sn = self.rows[self.cursor]; detail_w = bw - (detail_x - x) - 5
            status = curses.color_pair(6 if sn.safety == "dangerous" else 3) | curses.A_BOLD
            self.add(y + 7, detail_x, f"{sn.tool.upper()}  ·  {sn.category.upper()}", detail_w, status)
            self.add(y + 8, detail_x, "DANGEROUS" if sn.safety == "dangerous" else "SAFE", detail_w, curses.color_pair(6 if sn.safety == "dangerous" else 1) | curses.A_DIM)
            self.add(y + 10, detail_x, "COMMAND", detail_w, curses.color_pair(3) | curses.A_BOLD)
            for row, line in enumerate(textwrap.wrap(sn.command, max(10, detail_w - 1))[:2]): self.add(y + 11 + row, detail_x, line, detail_w, curses.color_pair(1) | curses.A_BOLD)
            if self.settings.show_descriptions:
                self.add(y + 14, detail_x, "ABOUT", detail_w, curses.color_pair(3) | curses.A_BOLD)
                for row, line in enumerate(textwrap.wrap(sn.description or "No description.", max(10, detail_w - 1))[:3]): self.add(y + 15 + row, detail_x, line, detail_w, curses.color_pair(1))
            if sn.tags: self.add(y + 19, detail_x, "# " + sn.tags, detail_w, curses.color_pair(1) | curses.A_DIM)
            self.add(y + bh - 5, detail_x, f"USED {sn.used}×  ·  ID {sn.id}", detail_w, curses.color_pair(1) | curses.A_DIM)
        else:
            self.add(y + 8, x + 5, "No snippets match.", bw - 10, curses.color_pair(5) | curses.A_BOLD)
            self.add(y + 10, x + 5, "Press n to add a snippet or / to clear the search.", bw - 10, curses.color_pair(1))
        footer = "↑↓/jk move   / search   n new   e edit   c copy   x run   d delete   ? help   q quit"
        self.add(y + bh - 2, x + 2, footer.center(bw - 4), bw - 4, curses.color_pair(4))
        if self.toast and time.time() < self.toast_until: self.add(y + bh - 3, x + 3, "• " + self.toast, bw - 6, curses.color_pair(5))
        self.s.refresh()

    def draw_compact(self, h, w):
        """Use a single-column layout before the split view becomes cramped."""
        bw, bh = min(w - 4, 100), min(h - 4, 28); x, y = (w - bw) // 2, (h - bh) // 2
        self.box(y, x, bh, bw, "TERM/INDEX")
        self.add(y + 1, x + 3, "SNIPPET VAULT", bw - 28, curses.color_pair(1) | curses.A_BOLD)
        self.add(y + 1, x + bw - 24, f"{len(self.rows):02d} MATCHES", 21, curses.color_pair(3))
        self.add(y + 2, x + 2, "─" * (bw - 4), bw - 4, curses.color_pair(3))
        self.add(y + 3, x + 3, "/ " + (self.query or "search title, command, tag..."), bw - 6, curses.color_pair(4) if self.query else curses.color_pair(1) | curses.A_DIM)
        self.add(y + 4, x + 2, "─" * (bw - 4), bw - 4, curses.color_pair(1))
        list_h = max(4, bh - 9)
        self.cursor = max(0, min(self.cursor, max(0, len(self.rows) - 1)))
        if self.cursor < self.offset: self.offset = self.cursor
        if self.cursor >= self.offset + list_h: self.offset = self.cursor - list_h + 1
        for i in range(list_h):
            idx = self.offset + i; yy = y + 5 + i
            if idx >= len(self.rows): break
            sn = self.rows[idx]; selected = idx == self.cursor
            marker = "▸" if selected else " "; safety = "!" if sn.safety == "dangerous" else "·"
            label = f"{marker} {safety} {sn.title}  ·  {sn.tool}/{sn.category}"
            attr = curses.color_pair(2) if selected else curses.color_pair(1)
            self.add(yy, x + 3, label, bw - 6, attr | (curses.A_BOLD if selected else 0))
        if self.rows:
            sn = self.rows[self.cursor]
            self.add(y + bh - 4, x + 3, textwrap.shorten(sn.command, width=max(12, bw - 8), placeholder="…"), bw - 6, curses.color_pair(1) | curses.A_BOLD)
            if self.settings.show_descriptions:
                self.add(y + bh - 3, x + 3, textwrap.shorten(sn.description or "No description.", width=max(12, bw - 8), placeholder="…"), bw - 6, curses.color_pair(1) | curses.A_DIM)
        else:
            self.add(y + bh - 4, x + 3, "No snippets match. Press n to create one.", bw - 6, curses.color_pair(5))
        footer = "↑↓/jk move  / search  n new  e edit  c copy  x run  ? help  q quit"
        self.add(y + bh - 2, x + 2, footer.center(bw - 4), bw - 4, curses.color_pair(4))
        if self.toast and time.time() < self.toast_until: self.add(y + bh - 3, x + 3, "• " + self.toast, bw - 6, curses.color_pair(5))
        self.s.refresh()

    def edit_line(self, y, x, width, value):
        text, cursor = value, len(value); self.s.timeout(-1)
        try: curses.curs_set(1)
        except curses.error: pass
        while True:
            start = max(0, min(cursor - width + 1, len(text) - width + 1)); visible = text[start:start + width]
            self.add(y, x, visible.ljust(width), width, curses.color_pair(1))
            try: self.s.move(y, x + min(cursor - start, width - 1)); self.s.refresh()
            except curses.error: pass
            key = self.s.getch()
            if key in (10, 13): result = text; break
            if key == 27: result = None; break
            if key in (curses.KEY_BACKSPACE, 127, 8) and cursor: text = text[:cursor - 1] + text[cursor:]; cursor -= 1
            elif key == curses.KEY_LEFT: cursor = max(0, cursor - 1)
            elif key == curses.KEY_RIGHT: cursor = min(len(text), cursor + 1)
            elif key in (curses.KEY_HOME, 1): cursor = 0
            elif key in (curses.KEY_END, 5): cursor = len(text)
            elif key == 21: text, cursor = text[:cursor].rstrip(), len(text[:cursor].rstrip())
            elif 32 <= key <= 126: text = text[:cursor] + chr(key) + text[cursor:]; cursor += 1
        try: curses.curs_set(0)
        except curses.error: pass
        self.s.timeout(180)
        if result is None: return None
        result = result.strip(); return result if (result or value == "") else value

    def prompt(self, label, value="", allow_empty=False):
        h, w = self.s.getmaxyx(); width = min(max(38, w - 10), 86, w - 4); x = (w - width) // 2; y = max(2, h // 2 - 2)
        self.s.erase(); self.box(y - 2, x, 7, width, label.upper(), curses.color_pair(3)); self.add(y - 1, x + 3, "Enter to confirm  ·  Esc to cancel", width - 6, curses.color_pair(1) | curses.A_DIM); self.add(y + 1, x + 3, "> ", 2, curses.color_pair(3) | curses.A_BOLD); self.s.refresh()
        result = self.edit_line(y + 1, x + 5, width - 8, value)
        if result is None: return None
        return result if (result or allow_empty) else value

    def form(self, existing=None):
        vals = {k: getattr(existing, k, "") for k in ("title", "tool", "category", "command", "description", "tags", "safety")}
        for key, label in (("title", "Title"), ("tool", "Tool"), ("category", "Category"), ("command", "Command"), ("description", "Description"), ("tags", "Tags (comma separated)"), ("safety", "Safety: safe or dangerous")):
            vals[key] = self.prompt(label, vals[key])
            if vals[key] is None: return None
        vals["safety"] = "dangerous" if vals["safety"].lower().startswith("d") else "safe"
        return vals

    def save_form(self, existing=None):
        try:
            data = self.form(existing)
            if data is None: return
            self.store.save(data, existing.id if existing else None)
            self.toast_msg("snippet updated" if existing else "snippet saved")
        except ValueError as error:
            self.toast_msg(str(error))

    def confirm(self, question):
        h, w = self.s.getmaxyx(); width = min(max(44, min(len(question) + 12, 86)), w - 4); x = (w - width) // 2
        lines = textwrap.wrap(question, max(10, width - 6)) or [""]; max_lines = max(1, h - 7)
        if len(lines) > max_lines: lines = lines[:max_lines]; lines[-1] = textwrap.shorten(lines[-1], max(10, width - 7), placeholder="…")
        height = len(lines) + 4; y = max(1, (h - height) // 2)
        self.box(y, x, height, width, "CONFIRM", curses.color_pair(5))
        for row, line in enumerate(lines): self.add(y + 1 + row, x + 3, line, width - 6, curses.color_pair(1))
        self.add(y + height - 2, x + 3, "y confirm   n / Esc cancel", width - 6, curses.color_pair(1) | curses.A_DIM)
        self.s.refresh(); self.s.timeout(-1); c = self.s.getch(); self.s.timeout(180); return c in (ord("y"), ord("Y"))

    def help(self):
        h, w = self.s.getmaxyx(); width = min(76, w - 4); height = 16; x = (w - width) // 2; y = max(1, (h - height) // 2)
        self.s.erase(); self.box(y, x, height, width, "KEYBOARD GUIDE", curses.color_pair(3))
        lines = ("Move        ↑ ↓ or j k", "Search      /", "New         n", "Edit        e", "Copy        c", "Run         x  (always asks first)", "Delete      d  (asks first)", "Onion       v  generate v3 identity", "Settings    s", "Import      i", "Export      o", "Quit        q or Esc", "", "Press any key to return")
        for row, line in enumerate(lines): self.add(y + 2 + row, x + 4, line, width - 8, curses.color_pair(1) | (curses.A_DIM if row == len(lines) - 1 else 0))
        self.s.refresh(); self.s.timeout(-1); self.s.getch(); self.s.timeout(180)

    def onion_progress(self, prefix, attempts, elapsed):
        h, w = self.s.getmaxyx(); width, height = min(78, w - 4), 12; x, y = (w - width) // 2, max(1, (h - height) // 2)
        spinner = "|/-\\"[(attempts // 8) % 4]
        self.s.erase(); self.box(y, x, height, width, "ONION IDENTITY", curses.color_pair(3))
        self.add(y + 2, x + 4, f"{spinner} searching v3 addresses", width - 8, curses.color_pair(3) | curses.A_BOLD)
        self.add(y + 4, x + 4, f"prefix      {prefix or '(random)'}", width - 8, curses.color_pair(1))
        self.add(y + 5, x + 4, f"attempts    {attempts:,}", width - 8, curses.color_pair(1))
        self.add(y + 6, x + 4, f"elapsed     {elapsed:.1f}s", width - 8, curses.color_pair(1))
        self.add(y + 8, x + 4, "private key remains in memory until you choose a save path", width - 8, curses.color_pair(1) | curses.A_DIM)
        self.add(y + height - 2, x + 2, "Esc cancel   ·   never share hs_ed25519_secret_key", width - 4, curses.color_pair(5))
        self.s.refresh(); self.s.timeout(0)
        key = self.s.getch(); self.s.timeout(180)
        if key in (27, ord("q")): raise OnionGenerationCancelled

    def onion_result(self, material, directory):
        h, w = self.s.getmaxyx(); width, height = min(92, w - 4), 13; x, y = (w - width) // 2, max(1, (h - height) // 2)
        self.s.erase(); self.box(y, x, height, width, "ONION IDENTITY READY", curses.color_pair(3))
        self.add(y + 2, x + 4, "ADDRESS", width - 8, curses.color_pair(3) | curses.A_BOLD)
        self.add(y + 3, x + 4, material.address, width - 8, curses.color_pair(1) | curses.A_BOLD)
        self.add(y + 5, x + 4, f"saved to   {directory}", width - 8, curses.color_pair(1))
        self.add(y + 6, x + 4, f"search     {material.attempts:,} attempts · {material.elapsed:.1f}s", width - 8, curses.color_pair(1))
        self.add(y + 8, x + 4, "The secret key is never displayed. Back up this directory securely.", width - 8, curses.color_pair(5))
        self.add(y + height - 2, x + 2, "Press any key to return", width - 4, curses.color_pair(4))
        self.s.refresh(); self.s.timeout(-1); self.s.getch(); self.s.timeout(180)

    def onion_identity(self):
        prefix = self.prompt("Vanity prefix (a-z, 2-7; blank for random)", "", allow_empty=True)
        if prefix is None: return
        prefix = prefix.lower().strip()
        if not ONION_PREFIX.fullmatch(prefix) or len(prefix) > 2:
            self.toast_msg("invalid prefix: use up to 2 chars a-z or 2-7"); return
        default_path = str(Path("~/.local/share/termindex/onion-services") / (prefix or "service"))
        directory = self.prompt("Save key directory", default_path)
        if directory is None: return
        try:
            material = generate_onion(prefix, lambda attempts, elapsed: self.onion_progress(prefix, attempts, elapsed))
            if not self.confirm(f"Save {material.address} to {directory}?"): self.toast_msg("identity discarded"); return
            saved = save_onion_material(material, directory)
            self.onion_result(material, saved)
        except OnionGenerationCancelled:
            self.toast_msg("onion search cancelled; no key was saved")
        except (FileExistsError, OSError, RuntimeError, TimeoutError) as error:
            self.toast_msg("onion generation failed: " + str(error)[:48])

    def settings_screen(self):
        options = [("Startup animation", "startup_animation"), ("Detail descriptions", "show_descriptions")]
        selected = 0
        while True:
            h, w = self.s.getmaxyx(); width, height = min(76, w - 4), 12; x, y = (w - width) // 2, max(1, (h - height) // 2)
            self.s.erase(); self.box(y, x, height, width, "SETTINGS", curses.color_pair(3))
            self.add(y + 2, x + 4, "Personalize the console. Changes save immediately.", width - 8, curses.color_pair(1) | curses.A_DIM)
            for row, (label, key) in enumerate(options):
                active = row == selected; value = "ON" if getattr(self.settings, key) else "OFF"
                attr = curses.color_pair(2) if active else curses.color_pair(1)
                self.add(y + 4 + row, x + 4, ("▸ " if active else "  ") + label, width - 20, attr | (curses.A_BOLD if active else 0))
                self.add(y + 4 + row, x + width - 14, f"[{value}]", 10, attr)
            self.add(y + 8, x + 4, "Space/Enter toggle   ↑↓ move   Esc return", width - 8, curses.color_pair(1) | curses.A_DIM)
            self.add(y + height - 2, x + 2, "settings are local to this user", width - 4, curses.color_pair(4))
            self.s.refresh(); self.s.timeout(-1); key = self.s.getch(); self.s.timeout(180)
            if key in (27, ord("q"), ord("s")): return
            if key in (curses.KEY_UP, ord("k")): selected = (selected - 1) % len(options)
            elif key in (curses.KEY_DOWN, ord("j")): selected = (selected + 1) % len(options)
            elif key in (10, 13, ord(" ")):
                name = options[selected][1]
                setattr(self.settings, name, not getattr(self.settings, name))
                try: self.settings.save(); self.toast_msg("settings saved")
                except OSError as error: self.toast_msg("settings failed: " + str(error)[:34])

    def run(self):
        self.startup()
        while True:
            self.draw(); c = self.s.getch()
            if c in (ord("q"), 27): return
            if c in (curses.KEY_DOWN, ord("j")): self.cursor += 1
            elif c in (curses.KEY_UP, ord("k")): self.cursor -= 1
            elif c == ord("/"):
                query = self.prompt("Search", self.query, allow_empty=True)
                if query is not None: self.query = query; self.cursor = 0; self.offset = 0
            elif c == ord("n"):
                self.save_form()
            elif c == ord("e") and self.rows:
                self.save_form(self.rows[self.cursor])
            elif c == ord("d") and self.rows:
                sn = self.rows[self.cursor]
                if self.confirm(f"Delete '{sn.title}'?"): self.store.delete(sn.id); self.cursor = max(0, self.cursor - 1); self.toast_msg("snippet deleted")
            elif c == ord("c") and self.rows:
                sn = self.rows[self.cursor]; tool = copy_snippet(self.store, sn); self.toast_msg("copied via " + tool if tool else "clipboard tool not found")
            elif c == ord("x") and self.rows:
                sn = self.rows[self.cursor]
                if self.confirm("Run command? " + sn.command) and (sn.safety != "dangerous" or self.confirm("DANGEROUS command. Run anyway?")):
                    self.store.touch(sn.id); self.s.timeout(-1); curses.def_prog_mode(); curses.endwin()
                    try:
                        result = subprocess.run(sn.command, shell=True, check=False)
                        input(f"\n[termindex] exit {result.returncode}; press Enter to return...")
                        self.toast_msg(f"command exited {result.returncode}")
                    finally:
                        curses.reset_prog_mode(); self.s = curses.initscr(); self.setup_terminal()
            elif c == ord("?"):
                self.help()
            elif c == ord("v"):
                self.onion_identity()
            elif c == ord("s"):
                self.settings_screen()
            elif c == ord("i"):
                path = self.prompt("Import JSON path")
                if path is None: continue
                try: self.store.import_json(path); self.toast_msg("import complete")
                except Exception as e: self.toast_msg("import failed: " + str(e)[:45])
            elif c == ord("o"):
                path = self.prompt("Export JSON path", "snippets.json")
                if path is None: continue
                try: self.store.export_json(path); self.toast_msg("exported to " + path)
                except Exception as e: self.toast_msg("export failed: " + str(e)[:45])

    def startup(self):
        if not self.settings.startup_animation: return
        h, w = self.s.getmaxyx(); frames = ("[ TERM/INDEX ]", "[ TERM/INDEX ]  .", "[ TERM/INDEX ]  ..", "[ TERM/INDEX ]  ...")
        for frame in frames:
            self.s.erase(); title = "  " + frame + "  "; x, y = max(0, (w - len(title)) // 2), max(0, h // 2 - 1)
            self.add(y, x, title, min(len(title), max(1, w - x)), curses.color_pair(3) | curses.A_BOLD)
            self.add(y + 2, x + 2, "loading local index", max(1, w - x - 2), curses.color_pair(1) | curses.A_DIM)
            self.s.refresh(); curses.napms(90)
        self.s.timeout(180)


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
        curses.wrapper(lambda s: UI(s, store, Settings.load()).run()); return 0
    finally:
        store.close()


if __name__ == "__main__": sys.exit(main())

