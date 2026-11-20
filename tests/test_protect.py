"""Git protection, end to end with real git: a private global git config and hooks folder per test."""
import os
import subprocess
import unittest

from repoguard import protect
from tests.helpers import GIT_ENV, LOADER, PAD, infect, tmpdir, write


class ProtectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        self.root = self.tmp.name
        self.gcfg = os.path.join(self.root, "gitconfig")
        with open(self.gcfg, "w") as fh:
            fh.write("[user]\n\tname = t\n\temail = t@t\n[init]\n\tdefaultBranch = main\n"
                     "[protocol \"file\"]\n\tallow = always\n")
        self.env = {**GIT_ENV, "GIT_CONFIG_GLOBAL": self.gcfg,
                    "REPOGUARD_HOOKS_DIR": os.path.join(self.root, "hooks"),
                    "REPOGUARD_STATE": os.path.join(self.root, "state"), "PATH": "/usr/bin:/bin"}
        self.env.pop("REPOGUARD_ALLOW_FETCH", None)
        self._old = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "REPOGUARD_HOOKS_DIR", "REPOGUARD_STATE")}
        os.environ.update({k: self.env[k] for k in self._old})
        os.makedirs(self.env["REPOGUARD_STATE"])
        # a "GitHub" repo with one clean commit, a developer who pushes to it, and you
        self.origin = os.path.join(self.root, "origin.git")
        self.dev = os.path.join(self.root, "dev")
        self.git(self.root, "init", "-q", "--bare", self.origin)
        self.git(self.root, "clone", "-q", self.origin, self.dev)
        write(self.dev, "a.js", "export const a = 1;\n")
        self.git(self.dev, "add", "-A")
        self.git(self.dev, "commit", "-qm", "c1")
        self.git(self.dev, "push", "-q", "origin", "HEAD:main")

    def tearDown(self):
        for k, v in self._old.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
        self.tmp.cleanup()

    def git(self, cwd, *args, check=True, extra=None):
        p = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, env={**self.env, **(extra or {})})
        if check and p.returncode:
            raise AssertionError(f"git {' '.join(args)}: {p.stderr}")
        return p

    def rev(self, cwd, ref):
        return self.git(cwd, "rev-parse", ref).stdout.strip()

    def push_infected(self, branch="main"):
        infect(self.dev)
        self.git(self.dev, "add", "-A")
        self.git(self.dev, "commit", "-qm", "looks normal")
        self.git(self.dev, "push", "-q", "origin", f"HEAD:{branch}")

    # ------------------------------------------------------------------ tests
    def test_on_off_status(self):
        self.assertEqual(protect.status(), "off")
        ok, _ = protect.install()
        self.assertTrue(ok)
        self.assertEqual(protect.status(), "on")
        for name in protect.ALL_HOOKS:
            self.assertTrue(os.access(os.path.join(self.env["REPOGUARD_HOOKS_DIR"], name), os.X_OK), name)
        protect.uninstall()
        self.assertEqual(protect.status(), "off")

    def test_infected_pull_is_cancelled_and_nothing_changes(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        before = (self.rev(me, "origin/main"), self.rev(me, "HEAD"))
        self.push_infected()
        p = self.git(me, "pull", "-q", "--ff-only", check=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("MALWARE", p.stderr)
        self.assertIn("postcss.config.mjs", p.stderr)
        self.assertEqual((self.rev(me, "origin/main"), self.rev(me, "HEAD")), before, "no ref moved")
        self.assertFalse(os.path.exists(os.path.join(me, "init")), "no infected file on disk")
        p = self.git(me, "fetch", "-q", check=False)
        self.assertNotEqual(p.returncode, 0)

    def test_infected_clone_is_cancelled(self):
        protect.install()
        self.push_infected()
        p = self.git(self.root, "clone", "-q", self.origin, os.path.join(self.root, "victim"), check=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.root, "victim", "init")))

    def test_infected_tag_is_cancelled(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        self.push_infected(branch="side")
        self.git(self.dev, "tag", "v9")
        self.git(self.dev, "push", "-q", "origin", "v9")
        p = self.git(me, "fetch", "-q", "origin", "refs/tags/v9:refs/tags/v9", check=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn("v9", self.git(me, "tag").stdout)

    def test_clean_updates_and_override_pass(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        write(self.dev, "b.js", "export const b = 2;\n")
        self.git(self.dev, "add", "-A")
        self.git(self.dev, "commit", "-qm", "clean")
        self.git(self.dev, "push", "-q", "origin", "HEAD:main")
        self.git(me, "pull", "-q", "--ff-only")
        self.assertTrue(os.path.exists(os.path.join(me, "b.js")))
        self.push_infected()
        self.git(me, "pull", "-q", "--ff-only", extra={"REPOGUARD_ALLOW_FETCH": "1"})
        self.assertTrue(os.path.exists(os.path.join(me, "init")), "override lets it through on purpose")

    def test_own_commits_are_not_checked(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        write(me, "notes.js", "x" + PAD + LOADER + "\n")
        self.git(me, "add", "-A")
        self.assertEqual(self.git(me, "commit", "-qm", "mine", check=False).returncode, 0)

    def test_repo_own_hooks_still_run(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        marker = os.path.join(self.root, "pre-commit-ran")
        hook = os.path.join(me, ".git", "hooks", "pre-commit")
        with open(hook, "w") as fh:
            fh.write(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(hook, 0o755)
        write(me, "c.js", "1;\n")
        self.git(me, "add", "-A")
        self.git(me, "commit", "-qm", "with hook")
        self.assertTrue(os.path.exists(marker), "repo's own pre-commit hook ran")
        # a failing repo hook still stops the commit, as it would without RepoGuard
        with open(hook, "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        write(me, "d.js", "2;\n")
        self.git(me, "add", "-A")
        self.assertNotEqual(self.git(me, "commit", "-qm", "blocked", check=False).returncode, 0)

    def test_repo_own_reference_transaction_failure_propagates(self):
        protect.install()
        me = os.path.join(self.root, "me")
        self.git(self.root, "clone", "-q", self.origin, me)
        hook = os.path.join(me, ".git", "hooks", "reference-transaction")
        with open(hook, "w") as fh:
            fh.write('#!/bin/sh\n[ "$1" = prepared ] && exit 1\nexit 0\n')
        os.chmod(hook, 0o755)
        write(me, "e.js", "3;\n")
        self.git(me, "add", "-A")
        self.assertNotEqual(self.git(me, "commit", "-qm", "x", check=False).returncode, 0)

    def test_does_not_replace_someone_elses_hooks_path(self):
        self.git(self.root, "config", "--global", "core.hooksPath", "/somewhere/else")
        ok, msg = protect.install()
        self.assertFalse(ok)
        self.assertIn("/somewhere/else", msg)
        self.assertEqual(protect.status(), "other")
        protect.uninstall()
        self.assertEqual(protect.current(), "/somewhere/else", "never unsets a path that isn't ours")
        ok, _ = protect.install(force=True)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
