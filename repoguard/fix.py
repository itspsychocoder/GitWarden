"""Fix malware on GitHub with a separate *fix token* that only lives in memory.

Two ways:
  * CommitFix       one normal cleanup commit on top of each infected branch (no force-push), via the API.
  * HistoryRewrite  rewrites every commit on every branch so the malware is gone from history, then
                    force-pushes (atomic, with lease). A full `git clone --mirror` backup is made first.

Nothing from the repo is ever run: files are read as data and git is called with hooks and the user's
git config turned off.
"""
import base64
import os
import shutil
import subprocess
import tempfile
import time
import urllib.parse

from . import config
from .clean import DELETE, EDIT, KEEP, MANUAL, clean
from .detect import Detector
from .github import GitHub, GitHubError

FIX_TOKEN_URL = "https://github.com/settings/personal-access-tokens/new"
TOKEN_LIST_URL = "https://github.com/settings/personal-access-tokens"
GIT_URL = os.environ.get("REPOGUARD_GIT_URL", "https://github.com/{owner}/{name}.git")
COMMIT_MESSAGE = "Remove malware (RepoGuard)"


def friendly(err):
    """Turn GitHub/git errors into something you can act on."""
    s = str(err)
    low = s.lower()
    if "workflow" in low and ("refusing" in low or "scope" in low or "permission" in low):
        return ("The fix token can't change workflow files. Give it Workflows: Read and write for this repo, "
                "then try again.")
    if "gh006" in low or "protected branch" in low or "cannot force-push" in low or "non_fast_forward" in low \
            or "rule violations" in low:
        return ("GitHub blocked the push: a branch protection rule or ruleset doesn't allow force pushes. Turn on "
                "'Allow force pushes' for these branches (Settings → Branches / Rules), run the fix, then turn it off.")
    if "stale info" in low or "not a fast forward" in low or "fetch first" in low:
        return "Someone pushed to this branch after the preview. Nothing was changed. Preview again."
    if "401" in s or "bad credentials" in low or "authentication failed" in low:
        return "GitHub rejected the fix token (wrong or expired). Create a new one."
    if "403" in s or "not accessible by personal access token" in low or "permission" in low and "denied" in low \
            or "write access" in low:
        return ("The fix token can't write to this repo. It needs Contents: Read and write on this repository "
                "(and Workflows: Read and write if workflow files change).")
    return s


def _q(name):
    return urllib.parse.quote(name, safe="")


# ====================================================================== branch protection

def protection(gh, repo, branch):
    """{'protected': bool, 'force_push': 'allowed'|'blocked'|'unknown', 'detail': str}"""
    _, b, _ = gh.request("GET", f"/repos/{repo}/branches/{_q(branch)}")
    out = {"protected": bool(b.get("protected")), "force_push": "allowed", "detail": ""}
    try:
        _, rules, _ = gh.request("GET", f"/repos/{repo}/rules/branches/{_q(branch)}")
        if any(r.get("type") == "non_fast_forward" for r in rules or []):
            out.update(force_push="blocked", detail="a ruleset blocks force pushes")
    except GitHubError:
        pass
    if out["protected"] and out["force_push"] != "blocked":
        try:
            _, p, _ = gh.request("GET", f"/repos/{repo}/branches/{_q(branch)}/protection")
            if not ((p or {}).get("allow_force_pushes") or {}).get("enabled"):
                out.update(force_push="blocked", detail="branch protection: 'Allow force pushes' is off")
        except GitHubError:
            out.update(force_push="unknown", detail="protected branch (couldn't read its settings)")
    return out


# ====================================================================== cleanup commit (API)

class CommitFix:
    def __init__(self, gh: GitHub, repo, detector=None, verdicts=None, progress=None):
        self.gh, self.repo = gh, repo
        self.det = detector or Detector()
        self.verdicts = dict(verdicts or {})
        self.progress = progress or (lambda m: None)

    def plan(self, branches):
        from .github import Watcher
        out = []
        for br in branches:
            self.progress(f"Reading {self.repo} · {br}")
            _, b, _ = self.gh.request("GET", f"/repos/{self.repo}/branches/{_q(br)}")
            head = b["commit"]["sha"]
            w = Watcher(self.gh, {"blob_verdicts": self.verdicts, "heads": {}, "findings": {}, "repos": [],
                                  "repos_etag": None}, self.det, budget=10_000)
            files, _ = w.scan_branch(self.repo, br, head)
            _, tree, _ = self.gh.request("GET", f"/repos/{self.repo}/git/trees/{head}?recursive=1")
            modes = {e["path"]: e["mode"] for e in tree.get("tree", [])}
            items = []
            for f in files:
                if f["severity"] != "danger":
                    continue
                data = self.gh.blob(self.repo, f["blob"]) if self.det.wants_content(f["path"]) else None
                p = clean(self.det, f["path"], data)
                if p.action == KEEP:
                    continue
                items.append({"path": f["path"], "mode": modes.get(f["path"], "100644"), "action": p.action,
                              "notes": p.notes, "rules": p.rules, "old": data, "new": p.new})
            out.append({"branch": br, "head": head, "files": items})
        return {"mode": "commit", "repo": self.repo, "branches": out}

    def apply(self, plan):
        results = []
        for br in plan["branches"]:
            changes, removed, edited = [], [], []
            for f in br["files"]:
                if f["action"] == EDIT:
                    _, blob, _ = self.gh.request("POST", f"/repos/{self.repo}/git/blobs",
                                                 {"content": base64.b64encode(f["new"]).decode(), "encoding": "base64"})
                    changes.append({"path": f["path"], "mode": f["mode"], "type": "blob", "sha": blob["sha"]})
                    edited.append(f["path"])
                elif f["action"] == DELETE:
                    changes.append({"path": f["path"], "mode": f["mode"], "type": "blob", "sha": None})
                    removed.append(f["path"])
            if not changes:
                results.append({"branch": br["branch"], "commit": None})
                continue
            self.progress(f"Pushing cleanup commit to {br['branch']}")
            _, commit, _ = self.gh.request("GET", f"/repos/{self.repo}/git/commits/{br['head']}")
            _, tree, _ = self.gh.request("POST", f"/repos/{self.repo}/git/trees",
                                         {"base_tree": commit["tree"]["sha"], "tree": changes})
            body = [COMMIT_MESSAGE, ""]
            body += [f"Deleted: {p}" for p in removed] + [f"Cleaned: {p}" for p in edited]
            _, new, _ = self.gh.request("POST", f"/repos/{self.repo}/git/commits",
                                        {"message": "\n".join(body) + "\n", "tree": tree["sha"], "parents": [br["head"]]})
            self.gh.request("PATCH", f"/repos/{self.repo}/git/refs/heads/{br['branch']}",
                            {"sha": new["sha"], "force": False})
            results.append({"branch": br["branch"], "commit": new["sha"]})
        return results


# ====================================================================== history rewrite (local mirror)

def _auth_env(token):
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "SSH_ASKPASS"))}
    env.update({
        "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "3",
        # The token rides in the environment (only your user can read it), never in argv or on disk.
        "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_CONFIG_KEY_2": "protocol.file.allow", "GIT_CONFIG_VALUE_2": "always",
    })
    return env


class GitError(Exception):
    pass


class CatFile:
    """One long-running `git cat-file --batch` to read many blobs quickly."""

    def __init__(self, repo, env):
        self.p = subprocess.Popen(["git", "-C", repo, "cat-file", "--batch"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, env=env)

    def read(self, sha):
        self.p.stdin.write(sha.encode() + b"\n")
        self.p.stdin.flush()
        head = self.p.stdout.readline().split()
        if len(head) < 3:
            raise GitError(f"cannot read object {sha}")
        size = int(head[2])
        data = self.p.stdout.read(size)
        self.p.stdout.read(1)
        return data

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()
        finally:
            self.p.stdout.close()


class HistoryRewrite:
    """prepare() -> analyze() -> [choose files to delete] -> build() -> push(). Always call close()."""

    def __init__(self, repo, token, detector=None, progress=None, backup_root=None, url=None):
        self.repo = repo
        owner, name = repo.split("/", 1)
        self.url = url or GIT_URL.format(owner=owner, name=name, repo=repo)
        self.env = _auth_env(token)
        self.det = detector or Detector()
        self.progress = progress or (lambda m: None)
        self.backup_root = backup_root or globals()["backup_root"]()
        self.backup = self.work = self._tmp = None
        self.verdicts = {}      # (blob, path) -> Plan
        self.trees = {}         # old tree -> new tree
        self.mapping = {}       # old commit -> new commit
        self.result = None

    # ---------------------------------------------------------------- git helpers
    def git(self, *args, repo=None, data=None, env=None, check=True):
        p = subprocess.run(["git", "-C", repo or self.work, *args], input=data, capture_output=True,
                           env=env or self.env, timeout=3600)
        if check and p.returncode:
            raise GitError(p.stderr.decode("utf8", "replace").strip() or f"git {args[0]} failed")
        return p.stdout

    def _tree_entries(self, tree):
        out = []
        for rec in self.git("ls-tree", "-r", "-l", "-z", tree).split(b"\0"):
            if not rec:
                continue
            meta, path = rec.split(b"\t", 1)
            mode, typ, sha, size = meta.decode().split()
            if typ == "blob":
                out.append((mode, sha, int(size) if size != "-" else 0, path.decode("utf8", "surrogateescape")))
        return out

    def _verdict(self, cat, sha, size, path):
        key = (sha, path)
        v = self.verdicts.get(key)
        if v is None:
            data = None
            if self.det.wants_content(path) and size <= self.det.max_bytes:
                data = cat.read(sha)
            elif not any(h.severity == "danger" for h in self.det.check_path(path)):
                v = self.verdicts[key] = _KEEP_PLAN
                return v
            v = self.verdicts[key] = clean(self.det, path, data)
            if v.action != KEEP:
                v.old = data
        return v

    # ---------------------------------------------------------------- steps
    def prepare(self):
        """Mirror backup of the GitHub repo, plus a scratch copy to rewrite in."""
        os.makedirs(self.backup_root, mode=0o700, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(self.backup_root, f"{self.repo.replace('/', '__')}-{stamp}")
        self.backup, n = base + ".git", 1
        while os.path.exists(self.backup):  # never overwrite an earlier backup
            n += 1
            self.backup = f"{base}-{n}.git"
        self.progress("Backing up the whole repo (git clone --mirror)…")
        p = subprocess.run(["git", "clone", "--mirror", "--quiet", self.url, self.backup], capture_output=True,
                           env=self.env, timeout=3600, cwd=os.path.expanduser("~"))
        if p.returncode:
            shutil.rmtree(self.backup, ignore_errors=True)
            raise GitError(friendly(p.stderr.decode("utf8", "replace").strip()))
        self._tmp = tempfile.mkdtemp(prefix="repoguard-rewrite-")
        self.work = os.path.join(self._tmp, "work.git")
        p = subprocess.run(["git", "clone", "--bare", "--quiet", "--no-local", self.backup, self.work],
                           capture_output=True, env=self.env, cwd=self._tmp)
        if p.returncode:
            raise GitError(p.stderr.decode("utf8", "replace"))
        # bring every branch and tag across as local refs
        self.git("fetch", "--quiet", "--no-tags", self.backup, "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*")
        return self.backup

    def refs(self):
        out = self.git("for-each-ref", "--format=%(objectname) %(objecttype) %(*objectname) %(refname)",
                       "refs/heads", "refs/tags").decode().splitlines()
        heads, tags = {}, {}
        for line in out:
            parts = line.split(" ")
            sha, typ, peeled, ref = parts[0], parts[1], parts[2], " ".join(parts[3:])
            if ref.startswith("refs/heads/"):
                heads[ref[11:]] = sha
            else:
                tags[ref[10:]] = {"sha": sha, "annotated": typ == "tag", "commit": peeled or sha}
        return heads, tags

    def commits(self, *tips):
        """[(sha, tree, [parents])] oldest first, for all branches (or the given tips)."""
        out = self.git("log", "--topo-order", "--reverse", "--format=%H %T %P", *(tips or ["--branches"])).decode()
        rows = []
        for line in out.splitlines():
            f = line.split()
            if f:
                rows.append((f[0], f[1], f[2:]))
        return rows

    def analyze(self):
        """Find every infected file version anywhere in branch history. Nothing is changed yet."""
        heads, tags = self.refs()
        commits = self.commits()
        cat = CatFile(self.work, self.env)
        tree_hit, affected, files = {}, 0, {}
        try:
            for n, (sha, tree, _) in enumerate(commits):
                if n % 50 == 0:
                    self.progress(f"Scanning history: commit {n + 1} of {len(commits)}")
                if tree not in tree_hit:
                    hit = False
                    for mode, blob, size, path in self._tree_entries(tree):
                        v = self._verdict(cat, blob, size, path)
                        if v.action == KEEP:
                            continue
                        hit = True
                        f = files.setdefault(path, {"path": path, "versions": set(), "actions": set(), "notes": [],
                                                    "rules": set(), "example": None})
                        if blob not in f["versions"]:
                            f["versions"].add(blob)
                            f["actions"].add(v.action)
                            f["rules"] |= set(v.rules)
                            f["notes"] = f["notes"] or list(v.notes)
                            if f["example"] is None and v.action == EDIT:
                                f["example"] = (v.old, v.new)
                    tree_hit[tree] = hit
                affected += tree_hit[tree]
        finally:
            cat.close()
        for f in files.values():
            f["versions"] = len(f["versions"])
            f["action"] = MANUAL if MANUAL in f["actions"] else (DELETE if f["actions"] == {DELETE} else EDIT)
            f["actions"], f["rules"] = sorted(f["actions"]), sorted(f["rules"])
        return {"repo": self.repo, "backup": self.backup, "commits_total": len(commits), "commits_affected": affected,
                "branches": heads, "tags": tags, "files": sorted(files.values(), key=lambda f: f["path"])}

    def _new_tree(self, cat, tree, delete_paths):
        if tree in self.trees:
            return self.trees[tree]
        changes = []
        for mode, sha, size, path in self._tree_entries(tree):
            v = self._verdict(cat, sha, size, path)
            if v.action == DELETE or (v.action == MANUAL and path in delete_paths):
                changes.append(b"0 " + b"0" * 40 + b"\t" + path.encode("utf8", "surrogateescape") + b"\0")
            elif v.action == EDIT:
                if not hasattr(v, "blob"):
                    v.blob = self.git("hash-object", "-w", "--stdin", data=v.new).decode().strip()
                changes.append(f"{mode} {v.blob}\t".encode() + path.encode("utf8", "surrogateescape") + b"\0")
        if not changes:
            self.trees[tree] = tree
            return tree
        idx = os.path.join(self._tmp, "index")
        env = {**self.env, "GIT_INDEX_FILE": idx}
        self.git("read-tree", tree, env=env)
        self.git("update-index", "-z", "--index-info", data=b"".join(changes), env=env)
        new = self.git("write-tree", env=env).decode().strip()
        os.remove(idx)
        self.trees[tree] = new
        return new

    def _new_commit(self, sha, parents, new_tree):
        raw = self.git("cat-file", "commit", sha)
        head, _, body = raw.partition(b"\n\n")
        kept, skip = [], False
        for line in head.split(b"\n"):
            if line.startswith(b" ") and skip:
                continue  # continuation of a dropped multi-line header (signature)
            key = line.split(b" ", 1)[0]
            skip = key in (b"tree", b"parent", b"gpgsig", b"gpgsig-sha256", b"mergetag")
            if not skip:
                kept.append(line)
        obj = b"tree " + new_tree.encode() + b"\n" + b"".join(b"parent " + p.encode() + b"\n" for p in parents)
        obj += b"\n".join(kept) + b"\n\n" + body
        return self.git("hash-object", "-t", "commit", "-w", "--stdin", data=obj).decode().strip()

    def build(self, delete_paths=()):
        """Rewrite history locally (nothing is pushed). Returns what push() would change."""
        delete_paths = set(delete_paths)
        self.trees, self.mapping = {}, {}  # start fresh: the files you chose to delete may have changed
        commits = self.commits()
        cat = CatFile(self.work, self.env)
        try:
            for n, (sha, tree, parents) in enumerate(commits):
                if n % 50 == 0:
                    self.progress(f"Rewriting history: commit {n + 1} of {len(commits)}")
                new_tree = self._new_tree(cat, tree, delete_paths)
                new_parents = [self.mapping.get(p, p) for p in parents]
                if new_tree == tree and new_parents == parents:
                    self.mapping[sha] = sha
                else:
                    self.mapping[sha] = self._new_commit(sha, new_parents, new_tree)
        finally:
            cat.close()
        heads, tags = self.refs()
        branches = [{"branch": b, "old": s, "new": self.mapping.get(s, s)} for b, s in sorted(heads.items())]
        moved_tags, stuck_tags = [], []
        for t, info in sorted(tags.items()):
            new = self.mapping.get(info["commit"], info["commit"])
            if new != info["commit"]:
                (stuck_tags if info["annotated"] else moved_tags).append({"tag": t, "old": info["sha"], "new": new})
        self.result = {"branches": [b for b in branches if b["old"] != b["new"]], "tags": moved_tags,
                       "annotated_tags_left": [t["tag"] for t in stuck_tags],
                       "commits_rewritten": sum(1 for k, v in self.mapping.items() if k != v)}
        self.result["left_for_you"], self.result["failed"] = self.verify([b["new"] for b in branches])
        if self.result["failed"]:
            raise GitError("Cleaning check failed for: " + ", ".join(self.result["failed"]) + ". Nothing was pushed.")
        return self.result

    def verify(self, tips):
        """Re-scan every commit of the new history.
        Returns (left_for_you, failed): files you chose to leave, and files that should have been cleaned but weren't."""
        left, failed, seen = set(), set(), set()
        cat = CatFile(self.work, self.env)
        try:
            for _, tree, _ in self.commits(*dict.fromkeys(tips)):
                if tree in seen:
                    continue
                seen.add(tree)
                for mode, blob, size, path in self._tree_entries(tree):
                    v = self._verdict(cat, blob, size, path)  # cleaned blobs are new, so they get checked fresh
                    if v.action == MANUAL:
                        left.add(path)
                    elif v.action != KEEP:
                        failed.add(path)
        finally:
            cat.close()
        return sorted(left), sorted(failed)

    def push(self):
        """Atomic force-push with lease: either every branch/tag moves, or none does."""
        if not self.result:
            raise GitError("build() first")
        args = ["push", "--atomic", "--porcelain", "--no-verify"]
        specs = []
        for b in self.result["branches"]:
            args.append(f"--force-with-lease=refs/heads/{b['branch']}:{b['old']}")
            specs.append(f"{b['new']}:refs/heads/{b['branch']}")
        for t in self.result["tags"]:
            args.append(f"--force-with-lease=refs/tags/{t['tag']}:{t['old']}")
            specs.append(f"{t['new']}:refs/tags/{t['tag']}")
        if not specs:
            return "Nothing to push."
        self.progress("Force-pushing the cleaned history…")
        p = subprocess.run(["git", "-C", self.work, *args, self.url, *specs], capture_output=True, env=self.env,
                           timeout=3600)
        if p.returncode:
            raise GitError(friendly(p.stderr.decode("utf8", "replace") + p.stdout.decode("utf8", "replace")))
        return p.stdout.decode("utf8", "replace")

    def close(self):
        """Delete the scratch copy and drop the token. The backup stays."""
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None
        self.env = {}


def backup_root():
    return os.path.join(config.state_dir(), "backups")


def _inside(path, root):
    path, root = os.path.realpath(path), os.path.realpath(root)
    return path != root and path.startswith(root + os.sep)


def list_backups():
    """[(path, bytes, mtime)] of history-rewrite backups, newest first."""
    out = []
    root = backup_root()
    try:
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.isdir(p) and name.endswith(".git"):
                size = sum(os.path.getsize(os.path.join(d, f)) for d, _, fs in os.walk(p) for f in fs)
                out.append((p, size, os.path.getmtime(p)))
    except OSError:
        pass
    return sorted(out, key=lambda x: -x[2])


def delete_backup(path):
    """Delete one history-rewrite backup. Refuses anything outside RepoGuard's backup folder."""
    if not _inside(path, backup_root()) or not path.endswith(".git"):
        raise ValueError(f"not a RepoGuard backup: {path}")
    shutil.rmtree(path)


class _Keep:
    action = KEEP
    rules = []
    notes = []


_KEEP_PLAN = _Keep()
