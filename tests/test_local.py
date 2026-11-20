"""Local scan and clean, with real files and git repos in a temp folder."""
import os
import unittest

from gitwarden import local, localclean
from tests.helpers import LOADER, PAD, clean_project, git, infect, tmpdir, write


def _read(p):
    with open(p, "rb") as fh:
        return fh.read()


def danger(finding, where=None):
    return {(x["where"], x["path"]) for x in finding["files"] if x["severity"] == "danger"
            and (where is None or x["where"] == where)}


class LocalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.root = self.tmp.name
        os.environ["GITWARDEN_STATE"] = os.path.join(self.root, "state")
        os.environ["GITWARDEN_CONFIG"] = os.path.join(self.root, "config")
        os.makedirs(os.environ["GITWARDEN_STATE"])
        os.makedirs(os.environ["GITWARDEN_CONFIG"])
        self.code = os.path.join(self.root, "code")
        self.marker = os.path.join(self.root, "PWNED")
        # repo: clean main, infected commit on main, infected "feature" branch, infected files on disk,
        # a planted fsmonitor setting and a planted pre-commit hook (both would create PWNED if run)
        self.repo = os.path.join(self.code, "shop")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.name", "Dev")
        git(self.repo, "config", "user.email", "dev@example.com")
        clean_project(self.repo)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "clean")
        git(self.repo, "checkout", "-qb", "feature")
        infect(self.repo)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "forged on feature")
        git(self.repo, "checkout", "-q", "main")
        infect(self.repo)
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "forged on main")
        evil = os.path.join(self.root, "evil.sh")
        with open(evil, "w") as fh:
            fh.write(f"#!/bin/sh\ntouch {self.marker}\n")
        os.chmod(evil, 0o755)
        with open(os.path.join(self.repo, ".git", "config"), "a") as fh:
            fh.write(f"[core]\n\tfsmonitor = {evil}\n[alias]\n\tst = status\n")
        hook = os.path.join(self.repo, ".git", "hooks", "pre-commit")
        with open(hook, "w") as fh:
            fh.write(f"#!/bin/sh\ntouch {self.marker}\n")
        os.chmod(hook, 0o755)
        # a plain folder (no git) with a dropped loader
        self.plain = os.path.join(self.code, "scripts")
        write(self.plain, "init", "x" + PAD + LOADER + "\n")
        write(self.plain, "ok.js", "export const ok = 1;\n")

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self):
        s = local.load_state()
        local.Scanner(s, [self.code]).run()
        return s

    def test_scan_finds_disk_branches_config_and_hooks(self):
        s = self.scan()
        f = s["findings"][self.repo]
        self.assertTrue({("disk", "postcss.config.mjs"), ("disk", "init"), ("disk", "package.json"),
                         ("disk", ".gitignore")} <= danger(f))
        self.assertTrue({("branch:feature", "init"), ("branch:main", "postcss.config.mjs")} <= danger(f))
        self.assertIn(("git", ".git/config"), danger(f))
        self.assertIn(".git/hooks/pre-commit", {x["path"] for x in f["files"] if x["severity"] == "review"})
        self.assertEqual(danger(s["findings"][self.plain]), {("disk", "init")})
        self.assertNotIn(("disk", "ok.js"), danger(s["findings"][self.plain]))
        self.assertFalse(os.path.exists(self.marker), "scanning never runs anything from the repo")

    def test_second_scan_uses_cache_and_sees_changes(self):
        s = self.scan()
        files_before = dict(s["files"])
        local.Scanner(s, [self.code]).run()
        self.assertEqual(s["files"], files_before)
        write(self.plain, "init", "harmless\n")
        os.utime(os.path.join(self.plain, "init"), (1, 1))
        local.Scanner(s, [self.code]).run()
        self.assertEqual(danger(s["findings"].get(self.plain, {"files": []})), set())

    def test_clean_everything_then_undo(self):
        s = self.scan()
        before = {p: _read(os.path.join(self.repo, p)) for p in ("postcss.config.mjs", "package.json", "init")}
        cfg_before = _read(os.path.join(self.repo, ".git", "config"))
        heads_before = {b: git(self.repo, "rev-parse", b).decode().strip() for b in ("main", "feature")}

        pl = localclean.plan(self.repo, s["findings"][self.repo])
        self.assertEqual(pl["current"], "main")
        self.assertEqual({f["path"]: f["action"] for f in pl["disk"]},
                         {"postcss.config.mjs": "edit", "package.json": "edit", ".gitignore": "edit", "init": "delete"})
        self.assertIn("feature", pl["branches"])
        res = localclean.apply(pl, commit_current=True, branches=["feature"])
        self.assertFalse(os.path.exists(self.marker), "repo hooks / fsmonitor never ran")

        # disk cleaned, config line gone (rest kept), both branches got one cleanup commit on top
        self.assertEqual(_read(os.path.join(self.repo, "postcss.config.mjs")),
                         b"export default { plugins: {} };\n")
        self.assertFalse(os.path.exists(os.path.join(self.repo, "init")))
        cfg = _read(os.path.join(self.repo, ".git", "config"))
        self.assertNotIn(b"fsmonitor", cfg)
        self.assertIn(b"st = status", cfg)
        for b in ("main", "feature"):
            self.assertEqual(git(self.repo, "rev-parse", f"{b}^").decode().strip(), heads_before[b])
            self.assertIn(b"Remove malware (GitWarden)", git(self.repo, "log", "-1", "--format=%B", b))
        self.assertEqual(git(self.repo, "log", "-1", "--format=%an", "feature").decode().strip(), "Dev")
        self.assertEqual(git(self.repo, "status", "--porcelain").decode().strip(), "", "working tree matches commit")
        s2 = self.scan()
        left = danger(s2["findings"].get(self.repo, {"files": []}))
        self.assertEqual({x for x in left if not x[0].startswith("remote:")}, set())
        # backups are not executable
        for dirpath, _, names in os.walk(res["undo"]):
            for n in names:
                self.assertFalse(os.access(os.path.join(dirpath, n), os.X_OK), n)

        # Undo puts every byte and branch back
        out = localclean.restore(res["undo"])
        self.assertEqual(sorted(out["branches"]), ["feature", "main"])
        for p, data in before.items():
            self.assertEqual(_read(os.path.join(self.repo, p)), data, p)
        self.assertEqual(_read(os.path.join(self.repo, ".git", "config")), cfg_before)
        self.assertEqual({b: git(self.repo, "rev-parse", b).decode().strip() for b in ("main", "feature")}, heads_before)

    def test_file_changed_after_preview_is_left_alone(self):
        s = self.scan()
        pl = localclean.plan(self.repo, s["findings"][self.repo])
        write(self.repo, "postcss.config.mjs", "export default { mine: true };" + PAD + LOADER + "\n")
        localclean.apply(pl)
        self.assertIn(b"mine: true", _read(os.path.join(self.repo, "postcss.config.mjs")))

    def test_plain_folder(self):
        s = self.scan()
        pl = localclean.plan(self.plain, s["findings"][self.plain])
        res = localclean.apply(pl)
        self.assertEqual(res["files"], 1)
        self.assertFalse(os.path.exists(os.path.join(self.plain, "init")))
        self.assertTrue(os.path.exists(os.path.join(self.plain, "ok.js")))
        self.assertEqual(localclean.backups()[0][0], res["undo"])
        with self.assertRaises(ValueError):
            localclean.delete_backup(self.plain)  # not a backup: refused
        localclean.delete_backup(res["undo"])
        self.assertEqual(localclean.backups(), [])


if __name__ == "__main__":
    unittest.main()
