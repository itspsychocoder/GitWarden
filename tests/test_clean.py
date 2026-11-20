import json
import unittest

from repoguard.clean import DELETE, EDIT, KEEP, MANUAL, clean
from repoguard.detect import Detector
from tests.helpers import LOADER, NPM_LOADER, PAD


class CleanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Detector()

    def c(self, path, text):
        return clean(self.d, path, text.encode() if isinstance(text, str) else text)

    def test_clean_file_is_kept(self):
        self.assertEqual(self.c("a.js", "export const a = 1;\n").action, KEEP)

    def test_offscreen_code_is_cut(self):
        p = self.c("postcss.config.mjs", "export default { plugins: {} };" + PAD + LOADER + "\nconst x = 1;\n")
        self.assertEqual(p.action, EDIT)
        self.assertEqual(p.new, b"export default { plugins: {} };\nconst x = 1;\n")

    def test_crlf_kept(self):
        p = self.c("a.js", "a();" + PAD + LOADER + "\r\nb();\r\n")
        self.assertEqual(p.new, b"a();\r\nb();\r\n")

    def test_gitignore_marker_lines_removed(self):
        p = self.c(".gitignore", "node_modules\nconfig.bat\n.env\n")
        self.assertEqual((p.action, p.new), (EDIT, b"node_modules\n.env\n"))

    def test_npm_loader_removed(self):
        p = self.c("package.json", NPM_LOADER)
        self.assertEqual(p.action, EDIT)
        self.assertEqual(json.loads(p.new)["scripts"], {"dev": "next dev", "build": "next build"})
        suffix = '{"scripts":{"dev":"next dev && node ' + 'init"}}'
        self.assertEqual(json.loads(self.c("package.json", suffix).new)["scripts"]["dev"], "next dev")
        only = '{"scripts":{"build":"next build","x":"node ' + 'init"}}'
        self.assertEqual(json.loads(self.c("package.json", only).new)["scripts"], {"build": "next build"})

    def test_vscode_autorun(self):
        auto = {"label": "x", "command": "node ./init", "runOptions": {"runOn": "folderOpen"}}
        mixed = {"version": "2.0.0", "tasks": [{"label": "build", "command": "npm run build"}, auto]}
        p = self.c(".vscode/tasks.json", json.dumps(mixed))
        self.assertEqual(p.action, EDIT)
        self.assertEqual([t["label"] for t in json.loads(p.new)["tasks"]], ["build"])
        p = self.c(".vscode/tasks.json", json.dumps({"version": "2.0.0", "tasks": [auto]}))
        self.assertEqual(p.action, DELETE)
        p = self.c(".vscode/tasks.json", '// comment\n{"tasks":[{"runOptions":{"runOn":"folderOpen"}}]}')
        self.assertEqual(p.action, MANUAL)

    def test_whole_file_payloads_deleted(self):
        self.assertEqual(self.c("config.bat", None).action, DELETE)
        self.assertEqual(self.c("init", "x" + PAD + LOADER).action, DELETE)
        self.assertEqual(self.c("fonts/a.woff2", "(function(){require('x')})").action, DELETE)

    def test_code_mixed_into_real_file_is_left_for_you(self):
        p = self.c("src/server.js", "import x from 'y';\n" + LOADER + "\nexport default x;\n")
        self.assertEqual(p.action, MANUAL)


if __name__ == "__main__":
    unittest.main()
