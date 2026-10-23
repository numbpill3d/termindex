import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parents[1]))
from termindex import Store, SEED


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


if __name__ == "__main__": unittest.main()

