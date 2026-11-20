"""Fix what the PC check found, with a backup of everything first and an Undo.

Order: stop dangerous processes (after checking the PID still runs the same program), then change files.
Everything that changes is copied to ~/.local/state/repoguard/quarantine/<time>-this-pc/ (never executable)
and listed in undo.json, so restore() can put it back. Stopped processes can't be restarted by Undo.
"""
import json
import os
import shutil
import signal
import stat
import subprocess
import time

from . import config, pc

SYSTEMCTL = os.environ.get("REPOGUARD_SYSTEMCTL") or "systemctl"


def _qdir():
    root = os.path.join(config.state_dir(), "quarantine")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    d, n = os.path.join(root, f"{stamp}-this-pc"), 1
    while os.path.exists(d):
        n += 1
        d = os.path.join(root, f"{stamp}-this-pc-{n}")
    os.makedirs(d, mode=0o700)
    return d


def _stash(qdir, src, name=None):
    """Copy src into qdir (not executable). Returns the backup path."""
    dest = os.path.join(qdir, "files", (name or src).lstrip("/"))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(src, dest)
    os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)
    return dest


def _save(qdir, undo):
    with open(os.path.join(qdir, "undo.json"), "w", encoding="utf8") as fh:
        json.dump(undo, fh, indent=1)


def _run(*args, data=None):
    return subprocess.run(list(args), input=data, capture_output=True, text=True, timeout=60)


def _same_process(pid, exe, cmd):
    """Is `pid` still the program we found? (PIDs get reused.)"""
    base = os.path.join(pc.PROC, str(pid))
    try:
        now_exe = os.readlink(os.path.join(base, "exe"))
    except OSError:
        now_exe = ""
    raw = pc._read(os.path.join(base, "cmdline"), 8000) or b""
    now_cmd = " ".join(a.decode("utf8", "replace") for a in raw.split(b"\0") if a)
    return bool(now_exe or now_cmd) and now_exe == exe and now_cmd == cmd


def _stop(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    for _ in range(20):
        time.sleep(0.1)
        if not os.path.exists(os.path.join(pc.PROC, str(pid))):
            return True
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    return True


def apply(findings):
    """Fix the given findings. Returns {"undo": qdir, "done": [...], "skipped": [(title, why)]}."""
    qdir = _qdir()
    undo = {"kind": "pc", "time": time.strftime("%Y%m%d-%H%M%S"), "root": "This PC", "files": [], "actions": [],
            "branches": []}
    done, skipped = [], []

    protected = pc._protected_pids()
    for f in [f for f in findings if (f.get("fix") or {}).get("type") == "kill"]:
        fx = f["fix"]
        if fx["pid"] in protected:
            skipped.append((f["title"], "RepoGuard never stops itself or the programs that started it"))
            continue
        if not _same_process(fx["pid"], fx["exe"], fx["cmd"]):
            skipped.append((f["title"], "already stopped (or the ID is now used by another program)"))
            continue
        _stop(fx["pid"])
        undo["actions"].append({"type": "killed", "pid": fx["pid"], "cmd": fx["cmd"]})
        done.append(f"Stopped {f['title']} (pid {fx['pid']})")
        _save(qdir, undo)

    for f in findings:
        fx = f.get("fix") or {}
        t = fx.get("type")
        try:
            if t == "quarantine":
                path = fx["path"]
                if not os.path.exists(path):
                    skipped.append((f["title"], "already gone"))
                    continue
                mode = os.stat(path).st_mode
                backup = _stash(qdir, path)
                os.remove(path)
                undo["files"].append({"path": path, "backup": backup, "action": "delete", "mode": mode})
                done.append(f"Moved {path} to the backup")
            elif t == "remove_line":
                path, line = fx["path"], fx["line"]
                with open(path, encoding="utf8", errors="surrogateescape", newline="") as fh:
                    text = fh.read()
                lines = text.splitlines(keepends=True)
                keep = [x for x in lines if x.rstrip("\r\n") != line]
                if len(keep) == len(lines):
                    skipped.append((f["title"], "line not there any more"))
                    continue
                backup = _stash(qdir, path)
                mode = os.stat(path).st_mode
                tmp = path + ".repoguard-tmp"
                with open(tmp, "w", encoding="utf8", errors="surrogateescape", newline="") as fh:
                    fh.write("".join(keep))
                os.chmod(tmp, stat.S_IMODE(mode))
                os.replace(tmp, path)
                undo["files"].append({"path": path, "backup": backup, "action": "edit", "mode": mode})
                done.append(f"Removed a line from {path}")
            elif t == "crontab_line":
                cur = _run(pc.CRONTAB, "-l")
                if cur.returncode:
                    skipped.append((f["title"], "couldn't read your crontab"))
                    continue
                backup = os.path.join(qdir, "crontab.txt")
                with open(backup, "w", encoding="utf8") as fh:
                    fh.write(cur.stdout)
                lines = cur.stdout.splitlines(keepends=True)
                keep = [x for x in lines if x.rstrip("\n") != fx["line"]]
                if len(keep) == len(lines):
                    skipped.append((f["title"], "line not there any more"))
                    continue
                r = _run(pc.CRONTAB, "-", data="".join(keep))
                if r.returncode:
                    skipped.append((f["title"], r.stderr.strip() or "crontab refused the change"))
                    continue
                undo["actions"].append({"type": "crontab", "backup": backup})
                done.append("Removed a scheduled command from your crontab")
            elif t == "systemd_user":
                unit, path = fx["unit"], fx["path"]
                enabled = _run(SYSTEMCTL, "--user", "is-enabled", unit).stdout.strip() == "enabled"
                active = _run(SYSTEMCTL, "--user", "is-active", unit).stdout.strip() == "active"
                _run(SYSTEMCTL, "--user", "disable", "--now", unit)
                if os.path.exists(path):
                    mode = os.stat(path).st_mode
                    backup = _stash(qdir, path)
                    os.remove(path)
                    undo["files"].append({"path": path, "backup": backup, "action": "delete", "mode": mode})
                _run(SYSTEMCTL, "--user", "daemon-reload")
                undo["actions"].append({"type": "systemd_user", "unit": unit, "enabled": enabled, "active": active})
                done.append(f"Stopped and removed service {unit}")
            elif t == "git_unset":
                gitconfig = os.path.join(pc.HOME, ".gitconfig")
                backup = _stash(qdir, gitconfig)
                mode = os.stat(gitconfig).st_mode
                r = _run("git", "config", "--file", gitconfig, "--unset-all", fx["key"])
                if r.returncode not in (0, 5):
                    skipped.append((f["title"], r.stderr.strip()))
                    continue
                undo["files"].append({"path": gitconfig, "backup": backup, "action": "edit", "mode": mode})
                done.append(f"Removed git setting {fx['key']}")
            elif t in ("manual", None):
                if t == "manual":
                    skipped.append((f["title"], fx["how"]))
                continue
        except OSError as e:
            skipped.append((f["title"], str(e)))
        _save(qdir, undo)
    _save(qdir, undo)
    return {"undo": qdir, "done": done, "skipped": skipped}


def restore(qdir):
    """Put back files, crontab and services from one fix. Stopped processes stay stopped."""
    with open(os.path.join(qdir, "undo.json"), encoding="utf8") as fh:
        undo = json.load(fh)
    n = 0
    for f in undo["files"]:
        os.makedirs(os.path.dirname(f["path"]), exist_ok=True)
        shutil.copy2(f["backup"], f["path"])
        os.chmod(f["path"], stat.S_IMODE(f["mode"]))
        n += 1
    for a in undo["actions"]:
        if a["type"] == "crontab":
            _run(pc.CRONTAB, a["backup"])
            n += 1
        elif a["type"] == "systemd_user":
            _run(SYSTEMCTL, "--user", "daemon-reload")
            if a["enabled"]:
                _run(SYSTEMCTL, "--user", "enable", a["unit"])
            if a["active"]:
                _run(SYSTEMCTL, "--user", "start", a["unit"])
    return {"files": n, "branches": []}
