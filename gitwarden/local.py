"""Scan the code on this computer: the files in your code folders, every local branch of each git repo,
each repo's .git/config (settings that make git run a program) and its .git/hooks.

Reads files and git objects as data; never runs anything it scans. Results are cached (files by
mtime+size, git blobs by ID), so after the first pass only what changed is read again.
"""
import os
import re
import subprocess
import time

from . import config
from .detect import DANGER, REVIEW, Detector, Hit, worst

MEDIA_HEAD = 8000          # a media/font file only needs its start checked (code disguised as media)
MAX_DEPTH = 8              # how deep under a watched folder to look for projects
# Git settings in a repo's own .git/config that make git run a program (the worm can plant these)
GIT_CONFIG_RULES = re.compile(
    rb"^\s*(?:fsmonitor\s*=\s*(?!false\b)\S|sshcommand\s*=|pager\s*=|editor\s*=|askpass\s*=|gitproxy\s*=|"
    rb"textconv\s*=|external\s*=|clean\s*=|smudge\s*=|process\s*=|hookspath\s*=|[\w.-]+\s*=\s*!)", re.M | re.I)
SAFE_GIT = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"]
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})

CONFIG_HIT = Hit("git_config_exec", DANGER, "Git setting that makes git run a program")
HOOK_HIT = Hit("repo_hook", REVIEW, "Git hook in this repo (runs on commit/checkout)")


def git(repo, *args, data=None):
    return subprocess.run([*SAFE_GIT, "-C", repo, *args], input=data, capture_output=True, env=GIT_ENV, timeout=600)


def default_folders():
    w = os.path.expanduser("~/Working")
    return [w if os.path.isdir(w) else os.path.expanduser("~")]


def state_path():
    return os.path.join(config.state_dir(), "local.json")


def load_state():
    s = config.load_json(state_path(), {})
    s.setdefault("files", {})        # abs path -> [mtime, size, [[rule, sev, label], ...]]
    s.setdefault("blobs", {})        # "sha|path" -> hits
    s.setdefault("heads", {})        # "repo|ref" -> sha scanned
    s.setdefault("findings", {})     # repo root -> {"where": [...]} see Scanner.run
    s.setdefault("last_check", None)
    return s


def save_state(s):
    for k, cap in (("blobs", 300_000), ("files", 300_000)):
        if len(s[k]) > cap:
            s[k] = dict(list(s[k].items())[-cap // 2:])
    config.save_json(state_path(), s)


def finding_ids(findings, danger_only=True):
    out = set()
    for repo, f in findings.items():
        for item in f.get("files", []):
            if danger_only and item["severity"] != DANGER:
                continue
            out.add(f"{repo}|{item['where']}|{item['path']}|{item.get('sig', '')}")
    return out


class Scanner:
    def __init__(self, state, folders, detector=None, progress=None):
        self.state = state
        self.folders = [os.path.abspath(os.path.expanduser(f)) for f in folders]
        self.det = detector or Detector()
        self.progress = progress or (lambda m: None)

    # ---------------------------------------------------------------- discovery
    def walk(self):
        """Yield (repo_root or None, abs file path) for every file under the watched folders,
        and collect git repos on the way."""
        self.repos = []
        for top in self.folders:
            if not os.path.isdir(top):
                continue
            stack = [(top, 0, None)]
            while stack:
                d, depth, repo = stack.pop()
                try:
                    entries = list(os.scandir(d))
                except OSError:
                    continue
                names = {e.name for e in entries}
                if ".git" in names:
                    repo = d
                    self.repos.append(d)
                for e in entries:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir():
                            if e.name == ".git" or e.name in self.det.skip_dirs or depth >= MAX_DEPTH:
                                continue
                            stack.append((e.path, depth + 1, repo))
                        elif e.is_file():
                            yield repo, e.path, e
                    except OSError:
                        continue

    # ---------------------------------------------------------------- files on disk
    def check_file(self, path, rel, entry):
        try:
            st = entry.stat()
        except OSError:
            return []
        cached = self.state["files"].get(path)
        if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
            return [Hit.from_list(h) for h in cached[2]]
        data = None
        if self.det.wants_content(rel) and st.st_size <= self.det.max_bytes:
            limit = MEDIA_HEAD if self.det.media.search(rel) else st.st_size
            try:
                with open(path, "rb") as fh:
                    data = fh.read(limit)
            except OSError:
                data = None
        hits = self.det.check(rel, data)
        self.state["files"][path] = [st.st_mtime, st.st_size, [h.as_list() for h in hits]]
        return hits

    # ---------------------------------------------------------------- git
    def check_branches(self, repo):
        """Hits for every local branch and remote-tracking branch tip (git objects, not the disk)."""
        out = []
        p = git(repo, "for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/remotes")
        if p.returncode:
            return out
        for line in p.stdout.decode("utf8", "replace").splitlines():
            sha, ref = line.split(" ", 1)
            if ref.endswith("/HEAD"):
                continue
            key = f"{repo}|{ref}"
            cache_key = key + "|files"
            if self.state["heads"].get(key) == sha and cache_key in self.state["heads"]:
                files = self.state["heads"][cache_key]
            else:
                files = self._scan_tree(repo, sha)
                self.state["heads"][key] = sha
                self.state["heads"][cache_key] = files
            where = ("branch:" + ref[11:]) if ref.startswith("refs/heads/") else ("remote:" + ref[13:])
            out += [dict(f, where=where) for f in files]
        return out

    def _scan_tree(self, repo, sha):
        p = git(repo, "ls-tree", "-r", "-l", "-z", sha)
        if p.returncode:
            return []
        items = []
        for rec in p.stdout.split(b"\0"):
            if not rec:
                continue
            meta, path = rec.split(b"\t", 1)
            mode, typ, blob, size = meta.decode().split()
            path = path.decode("utf8", "surrogateescape")
            if typ != "blob" or any(part in self.det.skip_dirs for part in path.split("/")[:-1]):
                continue
            items.append((blob, path, int(size) if size != "-" else 0))
        todo = [(b, p, s) for b, p, s in items if f"{b}|{p}" not in self.state["blobs"]]
        read = sorted({b for b, p, s in todo if self.det.wants_content(p) and s <= self.det.max_bytes})
        data = {}
        if read:
            out = git(repo, "cat-file", "--batch", data="\n".join(read).encode()).stdout
            i = 0
            while i < len(out):
                nl = out.index(b"\n", i)
                head = out[i:nl].split()
                if len(head) < 3:
                    break
                size = int(head[2])
                data[head[0].decode()] = out[nl + 1:nl + 1 + size]
                i = nl + 2 + size
        for b, p, s in todo:
            self.state["blobs"][f"{b}|{p}"] = [h.as_list() for h in self.det.check(p, data.get(b))]
        files = []
        for b, p, s in items:
            hits = [Hit.from_list(h) for h in self.state["blobs"][f"{b}|{p}"]]
            if hits:
                files.append({"path": p, "blob": b, "sig": b, "hits": [h.as_list() for h in hits],
                              "severity": worst(hits)})
        return files

    def check_git_dir(self, repo):
        """A repo's own .git/config and .git/hooks (only for a normal .git folder)."""
        gd = os.path.join(repo, ".git")
        out = []
        if not os.path.isdir(gd):
            return out
        try:
            with open(os.path.join(gd, "config"), "rb") as fh:
                cfg = fh.read(200_000)
            lines = [m.group(0).decode("utf8", "replace").strip() for m in GIT_CONFIG_RULES.finditer(cfg)]
            if lines:
                out.append({"path": ".git/config", "where": "git", "sig": "|".join(lines),
                            "hits": [CONFIG_HIT.as_list()], "severity": DANGER, "detail": lines})
        except OSError:
            pass
        hooks = os.path.join(gd, "hooks")
        try:
            for e in os.scandir(hooks):
                if e.is_file() and not e.name.endswith(".sample") and os.access(e.path, os.X_OK):
                    st = e.stat()
                    out.append({"path": f".git/hooks/{e.name}", "where": "git", "sig": f"{st.st_size}:{st.st_mtime}",
                                "hits": [HOOK_HIT.as_list()], "severity": REVIEW})
        except OSError:
            pass
        return out

    def _project_of(self, path):
        """For a file outside any git repo: its project folder, i.e. the first folder under the watched
        folder it lives in (or the watched folder itself for files directly in it)."""
        top = next((f for f in self.folders if path.startswith(f + os.sep)), os.path.dirname(path))
        first = os.path.relpath(path, top).split(os.sep)[0]
        cand = os.path.join(top, first)
        return cand if os.path.isdir(cand) else top

    # ---------------------------------------------------------------- one pass
    def run(self):
        st = self.state
        findings = {}
        seen_files = set()
        n = 0
        for repo, path, entry in self.walk():
            n += 1
            if n % 2000 == 0:
                self.progress(f"Checking files on this computer… {n}")
            seen_files.add(path)
            root = repo or self._project_of(path)
            rel = os.path.relpath(path, root)
            hits = self.check_file(path, rel, entry)
            if hits:
                findings.setdefault(root, {"repo": bool(repo), "files": []})["files"].append(
                    {"path": rel, "where": "disk", "sig": f"{entry.stat().st_size}", "hits": [h.as_list() for h in hits],
                     "severity": worst(hits)})
        for i, repo in enumerate(self.repos):
            self.progress(f"Checking git branches: {os.path.basename(repo)} ({i + 1}/{len(self.repos)})")
            extra = self.check_branches(repo) + self.check_git_dir(repo)
            if extra:
                findings.setdefault(repo, {"repo": True, "files": []})["files"] += extra
        # forget files that are gone, so the cache doesn't grow forever
        st["files"] = {p: v for p, v in st["files"].items() if p in seen_files}
        live = {f"{r}|" for r in self.repos}
        st["heads"] = {k: v for k, v in st["heads"].items() if any(k.startswith(x) for x in live)}
        st["findings"] = findings
        st["repos"] = sorted(self.repos)
        st["files_checked"] = n
        st["last_check"] = time.time()
        return {"files": n, "repos": len(self.repos)}


def summarize(findings):
    out = {"danger": 0, "review": 0, "places": 0}
    for f in findings.values():
        d = [x for x in f["files"] if x["severity"] == DANGER]
        out["danger"] += len(d)
        out["review"] += len(f["files"]) - len(d)
        out["places"] += bool(d)
    return out
