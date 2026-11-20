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
