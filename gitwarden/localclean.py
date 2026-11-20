"""Clean malware from the code on this computer, with a backup of everything first and an Undo.

plan()    works out, for one folder, what would change: files on disk (delete / cut / leave for you),
          infected local branches (a cleanup commit made without checking them out), and dangerous
          lines in the repo's .git/config. Nothing is changed.
apply()   backs up every file it touches to ~/.local/state/gitwarden/quarantine/<time>/, then changes them,
          and writes undo.json there.
restore() puts everything back from that backup.

Git is always run with the repo's hooks and fsmonitor turned off, so nothing from an infected repo runs.
"""
import hashlib
import json
import os
import shutil
import stat
import time

from . import config
from .clean import DELETE, EDIT, KEEP, MANUAL, clean
from .detect import DANGER, Detector
from .local import GIT_CONFIG_RULES, git

COMMIT_MESSAGE = "Remove malware (GitWarden)"


def quarantine_root():
    return os.path.join(config.state_dir(), "quarantine")


def _danger(items):
    return [x for x in items if x["severity"] == DANGER]


def _identity(root):
    def get(k):
        p = git(root, "config", "--get", k)
        return p.stdout.decode().strip() if p.returncode == 0 else ""
    return get("user.name") or "GitWarden", get("user.email") or "gitwarden@localhost"


def plan(root, finding, det=None):
    """What cleaning `root` would do. `finding` is the local scanner's entry for that folder."""
    det = det or Detector()
    items = _danger(finding["files"])
    out = {"root": root, "is_repo": finding.get("repo", False), "disk": [], "branches": {}, "remote": [],
           "git_config": None, "current": None}
    if out["is_repo"]:
        p = git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
        out["current"] = p.stdout.decode().strip() if p.returncode == 0 else None
    for x in items:
        if x["where"] == "disk":
            path = os.path.join(root, x["path"])
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
                mode = os.stat(path).st_mode
            except OSError:
                continue
            p = clean(det, x["path"], data)
            if p.action != KEEP:
                out["disk"].append({"path": x["path"], "action": p.action, "notes": p.notes, "rules": p.rules,
                                    "old": data, "new": p.new, "mode": mode})
        elif x["where"].startswith("branch:"):
            br = x["where"][7:]
            data = git(root, "cat-file", "blob", x["blob"]).stdout if det.wants_content(x["path"]) else None
            p = clean(det, x["path"], data)
            if p.action != KEEP:
                out["branches"].setdefault(br, []).append(
                    {"path": x["path"], "action": p.action, "notes": p.notes, "rules": p.rules, "old": data, "new": p.new})
        elif x["where"].startswith("remote:"):
            if x["where"][7:] not in out["remote"]:
                out["remote"].append(x["where"][7:])
        elif x["path"] == ".git/config":
            out["git_config"] = {"lines": x.get("detail", [])}
    # The checked-out branch: cleaning the files on disk is what matters; committing it is optional
    return out


def _backup(qdir, root, rel, src):
    dest = os.path.join(qdir, os.path.basename(root), rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(src, dest)
    os.chmod(dest, stat.S_IRUSR | stat.S_IWUSR)  # never leave a backed-up script executable
    return dest


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def apply(pl, delete_manual=(), commit_current=False, branches=()):
    """Do it. Returns a result dict including the undo folder. Order: back up, then change."""
    root = pl["root"]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    qdir = os.path.join(quarantine_root(), f"{stamp}-{os.path.basename(root)}")
    n = 1
    while os.path.exists(qdir):
        n += 1
        qdir = os.path.join(quarantine_root(), f"{stamp}-{os.path.basename(root)}-{n}")
    os.makedirs(qdir, mode=0o700)
    undo = {"root": root, "time": stamp, "files": [], "branches": [], "git_config": None}
    delete_manual = set(delete_manual)

    # 1. files on disk
    changed_tracked = []
    for f in pl["disk"]:
        action = DELETE if (f["action"] == MANUAL and f["path"] in delete_manual) else f["action"]
        if action not in (EDIT, DELETE):
            continue
        path = os.path.join(root, f["path"])
        try:
            with open(path, "rb") as fh:
                now = fh.read()
        except OSError:
            continue
        if _sha(now) != _sha(f["old"]):
            continue  # changed since the preview: leave it alone
        backup = _backup(qdir, root, f["path"], path)
        if action == DELETE:
            os.remove(path)
        else:
            tmp = path + ".gitwarden-tmp"
            with open(tmp, "wb") as fh:
                fh.write(f["new"])
            os.chmod(tmp, stat.S_IMODE(f["mode"]))
            os.replace(tmp, path)
        undo["files"].append({"path": path, "backup": backup, "action": action})
        changed_tracked.append(f["path"])
        undo_write(qdir, undo)

    # 2. dangerous lines in .git/config
    if pl.get("git_config") and pl["is_repo"]:
        cfg = os.path.join(root, ".git", "config")
        with open(cfg, "rb") as fh:
            text = fh.read()
        backup = _backup(qdir, root, ".git/config", cfg)
        # drop whole lines that make git run a program; keep everything else byte for byte
        new = b"\n".join(line for line in text.split(b"\n") if not GIT_CONFIG_RULES.match(line))
        with open(cfg, "wb") as fh:
            fh.write(new)
        undo["git_config"] = {"path": cfg, "backup": backup}
        undo_write(qdir, undo)

    name, email = _identity(root) if pl["is_repo"] else ("GitWarden", "gitwarden@localhost")
    ident = {"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email, "GIT_COMMITTER_NAME": name,
             "GIT_COMMITTER_EMAIL": email}

    # 3. commit the cleaned files on the checked-out branch (only those paths; hooks off)
    committed = None
    if commit_current and pl["is_repo"] and changed_tracked:
        tracked = [p for p in changed_tracked
                   if git(root, "ls-files", "--error-unmatch", "--", p).returncode == 0]
        if tracked:
            old = git(root, "rev-parse", "HEAD").stdout.decode().strip()
            p = _git_env(root, ident, "commit", "--no-verify", "--quiet", "-m", COMMIT_MESSAGE, "--only", "--", *tracked)
            if p.returncode == 0:
                committed = git(root, "rev-parse", "HEAD").stdout.decode().strip()
                undo["branches"].append({"branch": pl["current"], "old": old, "new": committed})
                undo_write(qdir, undo)

    # 4. cleanup commits on other infected local branches, without checking them out
    for br in branches:
        files = pl["branches"].get(br) or []
        if br == pl.get("current") or not files:
            continue
        old = git(root, "rev-parse", f"refs/heads/{br}").stdout.decode().strip()
        info = []
        for f in files:
            action = DELETE if (f["action"] == MANUAL and f["path"] in delete_manual) else f["action"]
            if action == DELETE:
                info.append(f"0 {'0' * 40}\t{f['path']}")
            elif action == EDIT:
                blob = git(root, "hash-object", "-w", "--stdin", data=f["new"]).stdout.decode().strip()
                mode = git(root, "ls-tree", old, "--", f["path"]).stdout.decode().split()[0]
                info.append(f"{mode} {blob}\t{f['path']}")
        if not info:
            continue
        idx = os.path.join(qdir, "index.tmp")
        env = {"GIT_INDEX_FILE": idx}
        _git_env(root, env, "read-tree", old)
        _git_env(root, env, "update-index", "--index-info", data=("\n".join(info) + "\n").encode())
        tree = _git_env(root, env, "write-tree").stdout.decode().strip()
        os.remove(idx)
        new = _git_env(root, ident, "commit-tree", tree, "-p", old, "-m", COMMIT_MESSAGE).stdout.decode().strip()
        if git(root, "update-ref", f"refs/heads/{br}", new, old).returncode == 0:
            undo["branches"].append({"branch": br, "old": old, "new": new})
            undo_write(qdir, undo)

    return {"undo": qdir, "files": len(undo["files"]), "committed": committed,
            "branches": [b["branch"] for b in undo["branches"]], "git_config": bool(undo["git_config"])}


def _git_env(root, extra, *args, data=None):
    import subprocess
    from .local import GIT_ENV, SAFE_GIT
    return subprocess.run([*SAFE_GIT, "-C", root, *args], input=data, capture_output=True,
                          env={**GIT_ENV, **extra}, timeout=600)


def undo_write(qdir, undo):
    with open(os.path.join(qdir, "undo.json"), "w", encoding="utf8") as fh:
        json.dump(undo, fh, indent=1)


def restore(qdir):
    """Put back everything one cleaning changed. Branches only move back if nobody moved them since."""
    with open(os.path.join(qdir, "undo.json"), encoding="utf8") as fh:
        undo = json.load(fh)
    put_back = 0
    for f in undo["files"]:
        os.makedirs(os.path.dirname(f["path"]), exist_ok=True)
        shutil.copy2(f["backup"], f["path"])
        put_back += 1
    if undo.get("git_config"):
        shutil.copy2(undo["git_config"]["backup"], undo["git_config"]["path"])
        put_back += 1
    moved = []
    for b in undo["branches"]:
        if git(undo["root"], "update-ref", f"refs/heads/{b['branch']}", b["old"], b["new"]).returncode == 0:
            moved.append(b["branch"])
    # a commit on the checked-out branch: put the index back too, so `git status` matches
    for b in undo["branches"]:
        cur = git(undo["root"], "symbolic-ref", "--quiet", "--short", "HEAD").stdout.decode().strip()
        if b["branch"] == cur and b["branch"] in moved:
            git(undo["root"], "reset", "--quiet", "--mixed", b["old"])
    return {"files": put_back, "branches": moved}


def delete_backup(qdir):
    """Delete one cleaning backup (Undo is no longer possible). Refuses anything outside the quarantine folder."""
    root = os.path.realpath(quarantine_root())
    real = os.path.realpath(qdir)
    if real == root or not real.startswith(root + os.sep) or not os.path.exists(os.path.join(real, "undo.json")):
        raise ValueError(f"not a GitWarden backup: {qdir}")
    shutil.rmtree(real)


def backups():
    """[(folder, undo dict)] newest first."""
    root = quarantine_root()
    out = []
    try:
        for name in sorted(os.listdir(root), reverse=True):
            p = os.path.join(root, name, "undo.json")
            if os.path.exists(p):
                with open(p, encoding="utf8") as fh:
                    out.append((os.path.join(root, name), json.load(fh)))
    except OSError:
        pass
    return out
