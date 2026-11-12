import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
from termindex import ONION_SECRET_HEADER, OnionMaterial, Settings, Store, SEED, copy_snippet, onion_address, save_onion_material


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "snippets.db")

    def tearDown(self): self.tmp.cleanup()

    def test_seeds_and_searches(self):
        self.assertEqual(self.store.count(), len(SEED))
        self.assertTrue(any(s.tool == "docker" for s in self.store.all("docker")))

    def test_save_update_delete_and_roundtrip(self):
        data = dict(title="Test", tool="test", category="misc", command="printf hi", description="hello", tags="x", safety="safe")
        self.store.save(data); found = self.store.all("Test")[0]
        data["title"] = "Updated"; self.store.save(data, found.id)
        self.assertEqual(self.store.get(found.id).title, "Updated")
        path = Path(self.tmp.name) / "export.json"; self.store.export_json(path)
        self.assertTrue(json.loads(path.read_text()))
        self.store.delete(found.id); self.assertIsNone(self.store.get(found.id))

    def test_validation_normalizes_tags_and_safety(self):
        self.store.save({"title": " Clean ", "tool": "x", "category": "misc", "command": "echo hi", "description": "", "tags": " one, ,two ", "safety": "DANGEROUS"})
        item = self.store.all("Clean")[0]
        self.assertEqual(item.tags, "one,two")
        self.assertEqual(item.safety, "dangerous")
        with self.assertRaises(ValueError):
            self.store.save({"title": "", "command": "echo hi"})

    def test_import_rejects_invalid_batch_without_partial_rows(self):
        path = Path(self.tmp.name) / "bad.json"
        path.write_text(json.dumps([{"title": "valid", "command": "echo hi"}, {"title": "missing command"}]))
        before = self.store.count()
        with self.assertRaises(ValueError): self.store.import_json(path)
        self.assertEqual(self.store.count(), before)

    def test_import_rejects_null_required_fields_without_partial_rows(self):
        path = Path(self.tmp.name) / "null.json"
        path.write_text(json.dumps([{"title": None, "command": "echo hi"}]))
        before = self.store.count()
        with self.assertRaises(ValueError): self.store.import_json(path)
        self.assertEqual(self.store.count(), before)

    def test_copy_only_counts_successful_clipboard_writes(self):
        snippet = self.store.all()[0]
        with patch("termindex.clip", return_value=None):
            self.assertIsNone(copy_snippet(self.store, snippet))
        self.assertEqual(self.store.get(snippet.id).used, 0)

        with patch("termindex.clip", return_value="wl-copy"):
            self.assertEqual(copy_snippet(self.store, snippet), "wl-copy")
        self.assertEqual(self.store.get(snippet.id).used, 1)

    def test_settings_roundtrip_and_invalid_file_fallback(self):
        path = Path(self.tmp.name) / "settings.json"
        settings = Settings(startup_animation=False, show_descriptions=False)
        settings.save(path)
        self.assertEqual(Settings.load(path), settings)
        path.write_text("not json")
        self.assertEqual(Settings.load(path), Settings())

    def test_onion_address_encoding_and_key_export(self):
        public_key = bytes(range(32))
        address = onion_address(public_key)
        self.assertEqual(len(address), 62)
        self.assertTrue(address.endswith(".onion"))
        material = OnionMaterial(address, b"s" * 32, public_key, 1, 0.1)
        target = save_onion_material(material, Path(self.tmp.name) / "onion")
        self.assertEqual((target / "hostname").read_text(), address + "\n")
        self.assertEqual((target / "hs_ed25519_secret_key").stat().st_mode & 0o777, 0o600)
        expanded = bytearray(hashlib.sha512(b"s" * 32).digest())
        expanded[0] &= 248; expanded[31] &= 63; expanded[31] |= 64
        self.assertEqual((target / "hs_ed25519_secret_key").read_bytes(), ONION_SECRET_HEADER + bytes(expanded))
        with self.assertRaises(FileExistsError): save_onion_material(material, target)


if __name__ == "__main__": unittest.main()

