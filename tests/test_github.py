import os
import unittest

from repoguard import github
from tests.helpers import MockGitHub, infect, git, tmpdir


class WatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.root = self.tmp.name
        os.environ["REPOGUARD_STATE"] = os.path.join(self.root, "state")
        os.environ["REPOGUARD_CONFIG"] = os.path.join(self.root, "config")
        os.makedirs(os.environ["REPOGUARD_STATE"])
        os.makedirs(os.environ["REPOGUARD_CONFIG"])
        self.mock = MockGitHub()
        self.gh = github.GitHub("test-token", api=self.mock.url)

    def tearDown(self):
        self.mock.close()
        self.tmp.cleanup()

    def run_check(self, state, **kw):
        gh = github.GitHub("test-token", api=self.mock.url)
        return github.Watcher(gh, state, **kw).run()

    def test_clean_then_infected_then_fixed(self):
        repo = self.mock.add(self.root, "me/app")
        state = github.load_state()
        res = self.run_check(state)
        self.assertEqual(res["repos"], 1)
        self.assertEqual(state["findings"], {})
        self.assertIn("me/app:main", state["heads"])

        infect(repo.work)
        repo.commit("forged update", branch="feature")
        res = self.run_check(state)
        self.assertTrue(res["new"])
        files = {f["path"]: f for f in state["findings"]["me/app:feature"]}
        self.assertTrue({"postcss.config.mjs", "package.json", ".gitignore", "init"} <= set(files))
        self.assertEqual(files["postcss.config.mjs"]["severity"], "danger")
        self.assertNotIn("me/app:main", state["findings"])

        # Nothing changed: no file is downloaded again.
        before = self.mock.blob_calls()
        res = self.run_check(state)
        self.assertEqual(self.mock.blob_calls(), before)
        self.assertEqual(res["new"], [])
        self.assertEqual(res["branches_scanned"], 0)

        # Branch deleted: its findings go away.
        git(repo.bare, "branch", "-D", "feature")
        self.run_check(state)
        self.assertEqual(state["findings"], {})

    def test_unchanged_files_are_not_downloaded_again(self):
        repo = self.mock.add(self.root, "me/app")
        state = github.load_state()
        self.run_check(state)
        first = self.mock.blob_calls()
        with open(os.path.join(repo.work, "src", "b.js"), "w") as fh:
            fh.write("export const b = 2;\n")
        repo.commit("one new file")
        self.run_check(state)
        self.assertEqual(self.mock.blob_calls() - first, 1)

    def test_budget_resumes_next_time(self):
        repo = self.mock.add(self.root, "me/app")
        infect(repo.work)
        repo.commit("forged")
        state = github.load_state()
        res = self.run_check(state, budget=2)
        self.assertTrue(res["incomplete"])
        self.assertNotIn("me/app:main", state["heads"])
        res = self.run_check(state)
        self.assertFalse(res["incomplete"])
        self.assertIn("me/app:main", state["findings"])

    def test_big_first_scan_uses_one_archive_without_leaking_token(self):
        repo = self.mock.add(self.root, "me/big")
        for i in range(40):
            with open(os.path.join(repo.work, "src", f"m{i}.js"), "w") as fh:
                fh.write(f"export const m{i} = {i};\n")
        infect(repo.work)
        repo.commit("lots of files + forged")
        state = github.load_state()
        res = self.run_check(state)
        self.assertEqual(res["archives"], 1)
        self.assertLessEqual(self.mock.blob_calls(), 2, "files come from the archive, not one request each")
        self.assertIn("postcss.config.mjs", {f["path"] for f in state["findings"]["me/big:main"]})
        self.assertEqual(self.mock.codeload_auth, [None], "token must not be sent to the download server")

    def test_checkpoint_called_per_repo(self):
        self.mock.add(self.root, "me/a")
        self.mock.add(self.root, "me/b")
        calls = []
        github.Watcher(github.GitHub("test-token", api=self.mock.url), github.load_state(),
                       checkpoint=lambda: calls.append(1)).run()
        self.assertEqual(len(calls), 2)

    def test_quiet_checks_skip_unchanged_repos(self):
        a = self.mock.add(self.root, "me/a")
        self.mock.add(self.root, "me/b")
        state = github.load_state()
        self.run_check(state)
        self.assertEqual(self.mock.branch_list_calls(), 2)

        calls_before = len(self.mock.calls)
        res = self.run_check(state)  # nothing pushed: only the repo list is asked for
        self.assertEqual(self.mock.branch_list_calls(), 2)
        self.assertEqual(res["skipped"], 2)
        self.assertEqual(len(self.mock.calls) - calls_before, 1)
        self.assertEqual(len(state["heads"]), 2, "skipped repos keep their branches")

        infect(a.work)
        a.commit("forged", branch="evil")  # a push to repo a only
        res = self.run_check(state)
        self.assertEqual(self.mock.branch_list_calls(), 3)
        self.assertIn("me/a:evil", state["findings"])

    def test_full_sweep_uses_free_not_modified_answers(self):
        self.mock.add(self.root, "me/a")
        state = github.load_state()
        self.run_check(state)
        state["last_full_sweep"] = 0  # pretend 6 hours passed
        self.run_check(state)
        self.assertEqual(self.mock.not_modified, 1)
        self.assertGreater(state["last_full_sweep"], 0)

    def test_failed_branch_is_retried_next_time(self):
        a = self.mock.add(self.root, "me/a")
        state = github.load_state()
        real = github.Watcher.scan_branch
        github.Watcher.scan_branch = lambda *a, **k: (_ for _ in ()).throw(github.GitHubError(500, "boom"))
        try:
            res = self.run_check(state)
        finally:
            github.Watcher.scan_branch = real
        self.assertTrue(res["errors"])
        self.assertNotIn("me/a", state["repo_pushed"])
        self.run_check(state)
        self.assertIn("me/a:main", state["heads"])

    def test_review_notes_are_not_alerts(self):
        findings = {"me/a:main": [{"path": ".github/workflows/ci.yml", "blob": "b1", "severity": "review",
                                   "hits": [["autorun_location", "review", "File that can run code automatically"]]},
                                  {"path": "init", "blob": "b2", "severity": "danger",
                                   "hits": [["init_file", "review", "x"], ["known_code", "danger", "y"]]}]}
        self.assertEqual(github.finding_ids(findings, danger_only=True), {"me/a:main|init|b2|known_code"})
        self.assertEqual(len(github.finding_ids(findings)), 3)

    def test_summary_counts_only_infected_branches(self):
        review = {"path": "x.yml", "blob": "b", "severity": "review", "hits": [["autorun_location", "review", "x"]]}
        danger = {"path": "init", "blob": "c", "severity": "danger", "hits": [["known_code", "danger", "y"]]}
        c = github.summarize({"a:main": [review], "b:main": [review, danger], "c:dev": [danger]})
        self.assertEqual((c["branches"], c["danger"], c["review"]), (2, 2, 2))

    def test_state_round_trip(self):
        self.mock.add(self.root, "me/app")
        state = github.load_state()
        self.run_check(state)
        github.save_state(state)
        self.assertEqual(github.load_state()["heads"], state["heads"])
        mode = os.stat(github.state_path()).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_bad_token(self):
        gh = github.GitHub("wrong", api=self.mock.url)
        with self.assertRaises(github.GitHubError) as cm:
            github.Watcher(gh, github.load_state()).run()
        self.assertEqual(cm.exception.status, 401)

    def test_token_never_sent_outside_api(self):
        with self.assertRaises(github.GitHubError):
            self.gh.request("GET", "https://evil.example/steal")


if __name__ == "__main__":
    unittest.main()
