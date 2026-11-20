import os
import unittest

from repoguard import fix, github
from repoguard.clean import DELETE, EDIT, MANUAL
from tests.helpers import LOADER, MockGitHub, git, infect, tmpdir, write


class FixBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.root = self.tmp.name
        for k in ("STATE", "CONFIG"):
            os.environ[f"REPOGUARD_{k}"] = os.path.join(self.root, k.lower())
            os.makedirs(os.environ[f"REPOGUARD_{k}"])
        self.mock = MockGitHub()
        self.fix_gh = github.GitHub("fix-token", api=self.mock.url)
        self.watch_gh = github.GitHub("test-token", api=self.mock.url)

    def tearDown(self):
        self.mock.close()
        self.tmp.cleanup()

    def findings(self):
        state = github.load_state()
        github.Watcher(github.GitHub("test-token", api=self.mock.url), state).run()
        return state["findings"]

    def show(self, repo, rev, path):
        return git(repo.bare, "show", f"{rev}:{path}")


class CommitFixTest(FixBase):
    def setUp(self):
        super().setUp()
        self.repo = self.mock.add(self.root, "me/app")
        infect(self.repo.work)
        self.repo.commit("forged update", branch="feature/x")

    def test_cleanup_commit(self):
        old_head = git(self.repo.bare, "rev-parse", "feature/x").decode().strip()
        f = fix.CommitFix(self.fix_gh, "me/app")
        plan = f.plan(["feature/x"])
        actions = {x["path"]: x["action"] for x in plan["branches"][0]["files"]}
        self.assertEqual(actions, {"postcss.config.mjs": EDIT, "package.json": EDIT, ".gitignore": EDIT, "init": DELETE})
        res = f.apply(plan)
        new = res[0]["commit"]
        self.assertEqual(git(self.repo.bare, "rev-parse", "feature/x").decode().strip(), new)
        self.assertEqual(git(self.repo.bare, "rev-parse", new + "^").decode().strip(), old_head, "no force-push")
        self.assertEqual(self.show(self.repo, new, "postcss.config.mjs"), b"export default { plugins: {} };\n")
        self.assertIn(b"Remove malware (RepoGuard)", git(self.repo.bare, "log", "-1", "--format=%B", new))
        self.assertEqual(self.findings(), {})

    def test_watch_token_cannot_fix(self):
        f = fix.CommitFix(self.watch_gh, "me/app")
        plan = f.plan(["feature/x"])
        with self.assertRaises(github.GitHubError) as cm:
            f.apply(plan)
        self.assertIn("Contents: Read and write", fix.friendly(cm.exception))

    def test_branch_moved_after_preview(self):
        f = fix.CommitFix(self.fix_gh, "me/app")
        plan = f.plan(["feature/x"])
        write(self.repo.work, "other.txt", "hi\n")
        self.repo.commit("someone else pushed", branch="feature/x")
        with self.assertRaises(github.GitHubError) as cm:
            f.apply(plan)
        self.assertIn("Preview again", fix.friendly(cm.exception))


class ProtectionTest(FixBase):
    def test_protection_states(self):
        self.mock.add(self.root, "me/app")
        self.assertEqual(fix.protection(self.fix_gh, "me/app", "main")["force_push"], "allowed")
        self.mock.protected["me/app:main"] = "ruleset"
        self.assertEqual(fix.protection(self.fix_gh, "me/app", "main")["force_push"], "blocked")
        self.mock.protected["me/app:main"] = "protection"
        p = fix.protection(self.fix_gh, "me/app", "main")
        self.assertEqual((p["protected"], p["force_push"]), (True, "blocked"))
        self.mock.protected["me/app:main"] = "allowed"
        self.assertEqual(fix.protection(self.fix_gh, "me/app", "main")["force_push"], "allowed")


class HistoryRewriteTest(FixBase):
    def setUp(self):
        super().setUp()
        self.repo = r = self.mock.add(self.root, "me/app")
        self.clean_sha = git(r.bare, "rev-parse", "main").decode().strip()
        infect(r.work)
        r.commit("forged: looks like a normal commit")
        git(r.work, "tag", "v1")
        git(r.work, "push", "-q", "origin", "v1")
        r.commit("branch off the infected commit", branch="feature")
        git(r.work, "checkout", "-q", "main")
        write(r.work, "src/b.js", "export const b = 2;\n")
        r.commit("real work on top of the infection")
        self.url = r.bare
        self.log_before = self.log("main")

    def log(self, ref):
        return git(self.repo.bare, "log", "--format=%an|%ae|%ad|%cn|%cd|%s", ref).decode()

    def rewrite(self):
        return fix.HistoryRewrite("me/app", "fix-token", url=self.url,
                                  backup_root=os.path.join(self.root, "backups"))

    def test_rewrite_removes_malware_from_all_history(self):
        rw = self.rewrite()
        try:
            backup = rw.prepare()
            a = rw.analyze()
            self.assertEqual(a["commits_total"], 4)
            self.assertEqual(a["commits_affected"], 3)
            self.assertEqual({f["path"]: f["action"] for f in a["files"]},
                             {"postcss.config.mjs": EDIT, "package.json": EDIT, ".gitignore": EDIT, "init": DELETE})
            r = rw.build()
            self.assertEqual({b["branch"] for b in r["branches"]}, {"main", "feature"})
            self.assertEqual([t["tag"] for t in r["tags"]], ["v1"])
            self.assertEqual((r["left_for_you"], r["failed"]), ([], []))
            rw.push()
        finally:
            rw.close()
        bare = self.repo.bare
        # every commit on every branch and tag is clean now
        from repoguard.detect import Detector
        det = Detector()
        for c in git(bare, "rev-list", "--all").decode().split():
            for line in git(bare, "ls-tree", "-r", c).decode().splitlines():
                meta, path = line.split("\t", 1)
                data = git(bare, "cat-file", "blob", meta.split()[2])
                self.assertFalse([h for h in det.check(path, data) if h.severity == "danger"], (c, path))
        # untouched history before the infection keeps its SHA; authors, dates and messages are kept
        self.assertEqual(git(bare, "rev-list", "--max-parents=0", "main").decode().strip(), self.clean_sha)
        self.assertEqual(self.log("main"), self.log_before)
        self.assertEqual(self.show(self.repo, "main", "src/b.js"), b"export const b = 2;\n")
        # the backup still has the original (infected) history
        self.assertIn(b"forged", git(backup, "log", "--all", "--format=%s"))
        self.assertTrue(git(backup, "cat-file", "-e", "v1:init") == b"")

    def test_push_is_atomic_and_refuses_if_branch_moved(self):
        rw = self.rewrite()
        try:
            rw.prepare()
            rw.analyze()
            rw.build()
            write(self.repo.work, "late.txt", "pushed meanwhile\n")
            self.repo.commit("late push")
            before = {b: git(self.repo.bare, "rev-parse", b).decode() for b in ("main", "feature")}
            with self.assertRaises(fix.GitError) as cm:
                rw.push()
            self.assertIn("Preview again", str(cm.exception))
            self.assertEqual({b: git(self.repo.bare, "rev-parse", b).decode() for b in ("main", "feature")}, before)
        finally:
            rw.close()

    def test_mixed_in_code_left_unless_you_choose_delete(self):
        write(self.repo.work, "src/server.js", "import x from 'y';\n" + LOADER + "\nexport default x;\n")
        self.repo.commit("more")
        rw = self.rewrite()
        try:
            rw.prepare()
            a = rw.analyze()
            self.assertEqual({f["path"]: f["action"] for f in a["files"]}["src/server.js"], MANUAL)
            r = rw.build()
            self.assertEqual(r["left_for_you"], ["src/server.js"])
        finally:
            rw.close()
        rw = self.rewrite()
        try:
            rw.prepare()
            rw.analyze()
            r = rw.build(delete_paths={"src/server.js"})
            self.assertEqual(r["left_for_you"], [])
        finally:
            rw.close()

    def test_delete_backup_only_inside_backup_folder(self):
        os.makedirs(os.path.join(fix.backup_root(), "me__app-1.git"))
        self.assertEqual(len(fix.list_backups()), 1)
        fix.delete_backup(fix.list_backups()[0][0])
        self.assertEqual(fix.list_backups(), [])
        for bad in (self.root, fix.backup_root(), os.path.join(fix.backup_root(), "..", "x.git"), "/tmp/x.git"):
            with self.assertRaises(ValueError):
                fix.delete_backup(bad)
        self.assertTrue(os.path.exists(self.root))

    def test_close_drops_token(self):
        rw = self.rewrite()
        rw.prepare()
        rw.close()
        self.assertEqual(rw.env, {})
        self.assertFalse(os.path.exists(rw.work))


if __name__ == "__main__":
    unittest.main()
