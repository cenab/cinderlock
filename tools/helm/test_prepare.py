import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("helm_prepare", Path(__file__).with_name("prepare.py"))
PREPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREPARE)


class PreparationFiles(unittest.TestCase):
    def test_legal_tree_retains_sources_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "vendor"
            source.mkdir()
            (source / "LICENSE").write_text("Admitted license fixture\n")
            package = source / "package"
            package.mkdir()
            (package / "source.go").write_text("package fixture\n")
            PREPARE.public_tree(source, root / "copied")
            self.assertEqual(PREPARE.digest(source / "LICENSE"), PREPARE.digest(root / "copied/LICENSE"))
            self.assertEqual((root / "copied/package/source.go").read_text(), "package fixture\n")
            (source / "linked").symlink_to(root / "outside")
            with self.assertRaises(ValueError):
                PREPARE.public_tree(source, root / "rejected")
            self.assertFalse((root / "rejected").exists())

    def test_regular_file_bound_and_link_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            large = root / "large"
            with large.open("wb") as output:
                output.truncate(1024 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                PREPARE.regular(large)
            (root / "link").symlink_to(large)
            with self.assertRaises(ValueError):
                PREPARE.regular(root / "link")


if __name__ == "__main__":
    unittest.main()
