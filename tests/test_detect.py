import os
import unittest

from gitwarden.detect import DANGER, Detector
from tests.helpers import LOADER, NPM_LOADER, PAD

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rules(hits):
    return {h.rule for h in hits}


class DetectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Detector()

    def test_clean_files(self):
        self.assertEqual(self.d.check("src/a.js", b"export const a = 1;\n"), [])
        self.assertEqual(self.d.check("package.json", b'{"scripts":{"dev":"next dev"}}'), [])
        self.assertEqual(self.d.check(".gitignore", b"node_modules\n.env\n"), [])

    def test_offscreen_loader(self):
        hits = self.d.check("postcss.config.mjs", ("export default {};" + PAD + LOADER).encode())
        self.assertTrue({"offscreen", "known_code"} <= rules(hits))
        self.assertTrue(all(h.severity == DANGER for h in hits))

    def test_npm_loader_and_init(self):
        self.assertIn("npm_loader", rules(self.d.check("package.json", NPM_LOADER.encode())))
        self.assertIn("init_file", rules(self.d.check("init", None)))

    def test_gitignore_marker(self):
        self.assertIn("gitignore_marker", rules(self.d.check(".gitignore", b"node_modules\nconfig.bat\n")))
        self.assertEqual(self.d.check("docs/notes.txt", b"config.bat\n"), [])

    def test_vscode_autorun(self):
        task = b'{"tasks":[{"label":"x","runOptions":{"runOn":"folderOpen"}}]}'
        self.assertIn("autorun", rules(self.d.check(".vscode/tasks.json", task)))

    def test_fake_media(self):
        self.assertIn("fake_media", rules(self.d.check("public/fonts/a.woff2", b"(function(){var a=require('x')})")))
        self.assertEqual(self.d.check("logo.png", b"\x89PNG\r\n\x1a\n\0\0\0IHDR"), [])

    def test_obfuscated(self):
        code = "".join(f"var _0x{i:04x}=1;" for i in range(25)).encode()
        self.assertIn("obfuscated_ids", rules(self.d.check("a.js", code)))
        self.assertNotIn("obfuscated_ids", rules(self.d.check("a.js", b"var _0xabcd=1;")))

    def test_vendored_code_not_flagged_for_padding(self):
        self.assertNotIn("offscreen", rules(self.d.check("node_modules/x/a.js", ("a" + PAD + "b").encode())))

    def test_own_source_is_clean(self):
        """GitWarden must never flag itself (so its own git hook can't block its own pulls)."""
        for dirpath, dirs, names in os.walk(ROOT):
            dirs[:] = [x for x in dirs if x not in (".git", "__pycache__")]
            for n in names:
                p = os.path.join(dirpath, n)
                rel = os.path.relpath(p, ROOT)
                with open(p, "rb") as fh:
                    hits = [h for h in self.d.check(rel, fh.read()) if h.severity == DANGER]
                self.assertEqual(hits, [], rel)


if __name__ == "__main__":
    unittest.main()
