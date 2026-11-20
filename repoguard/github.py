"""GitHub watch: checks every branch of every repo you can push to, and reports malware in new commits.

Only reads through the GitHub REST API (no clone, nothing is run). File verdicts are cached by blob
SHA, so after the first pass only files that actually changed are downloaded.
"""
import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import config
from .detect import Detector, Hit, worst

API = os.environ.get("REPOGUARD_GITHUB_API", "https://api.github.com")
BLOB_BUDGET = 1500        # max file downloads per check; the rest continue next time
MIN_RATE_LEFT = 200       # stop early to leave API headroom for you and other tools
MAX_CACHE = 300_000


class GitHubError(Exception):
    def __init__(self, status, msg):
        super().__init__(f"GitHub {status}: {msg}" if status else msg)
        self.status = status


class GitHub:
    def __init__(self, token, api=None):
        self.token = token
        self.api = (api or API).rstrip("/")
        self.remaining = None
        self.calls = 0

    def request(self, method, path, body=None, etag=None):
        url = path if path.startswith("http") else self.api + path
        if not url.startswith(self.api):  # never send the token anywhere else
            raise GitHubError(0, f"refusing to follow link outside the GitHub API: {url}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "RepoGuard-Linux")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if etag:
            req.add_header("If-None-Match", etag)
        self.calls += 1
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self._rate(r.headers)
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None), r.headers
        except urllib.error.HTTPError as e:
            with e:
                self._rate(e.headers)
                if e.code == 304:
                    return 304, None, e.headers
                try:
                    msg = json.loads(e.read()).get("message", "")
                except Exception:
                    msg = str(e.reason)
            raise GitHubError(e.code, msg) from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise GitHubError(0, f"network error: {e}") from None

    def _rate(self, headers):
        v = headers.get("X-RateLimit-Remaining") if headers else None
        if v is not None:
            self.remaining = int(v)

    def pages(self, path, etag=None):
        """GET every page. Returns (304, None, etag) when unchanged since etag."""
        status, data, headers = self.request("GET", path, etag=etag)
        if status == 304:
            return 304, None, etag
        new_etag = headers.get("ETag")
        items = list(data or [])
        link = headers.get("Link") or ""
        while 'rel="next"' in link:
            nxt = re.search(r'<([^>]+)>;\s*rel="next"', link).group(1)
            _, data, headers = self.request("GET", nxt)
            items += data or []
            link = headers.get("Link") or ""
        return 200, items, new_etag

    def user(self):
        return self.request("GET", "/user")[1]

    def blob(self, repo, sha):
        _, data, _ = self.request("GET", f"/repos/{repo}/git/blobs/{sha}")
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"])
        return (data.get("content") or "").encode()


# ---------------------------------------------------------------- state

def state_path():
    return os.path.join(config.state_dir(), "github.json")


def load_state():
    s = config.load_json(state_path(), {})
    s.setdefault("heads", {})          # "owner/repo:branch" -> sha fully scanned
    s.setdefault("findings", {})       # "owner/repo:branch" -> [{path, blob, hits}]
    s.setdefault("blob_verdicts", {})  # "sha|path" -> [[rule, severity, label], ...]
    s.setdefault("repos", [])
    s.setdefault("repos_etag", None)
    s.setdefault("last_check", None)
    s.setdefault("last_error", None)
    return s


def save_state(s):
    if len(s["blob_verdicts"]) > MAX_CACHE:
        s["blob_verdicts"] = dict(list(s["blob_verdicts"].items())[-MAX_CACHE // 2:])
    config.save_json(state_path(), s)


def finding_ids(findings):
    """Stable ids for every hit, to tell new alerts from ones already shown."""
    out = set()
    for key, files in findings.items():
        for f in files:
            for h in f["hits"]:
                out.add(f"{key}|{f['path']}|{f['blob']}|{h[0]}")
    return out


# ---------------------------------------------------------------- watcher

class Watcher:
    def __init__(self, gh, state, detector=None, budget=BLOB_BUDGET, progress=None):
        self.gh, self.state = gh, state
        self.det = detector or Detector()
        self.budget = budget
        self.progress = progress or (lambda msg: None)

    def repos(self):
        """Repos you can push to (not archived). Uses an ETag so an unchanged list costs no rate limit."""
        status, items, etag = self.gh.pages(
            "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=pushed",
            etag=self.state["repos_etag"] if self.state["repos"] else None)
        if status != 304:
            self.state["repos"] = [{"full_name": r["full_name"], "default_branch": r.get("default_branch"),
                                    "private": r.get("private", False), "html_url": r.get("html_url")}
                                   for r in items if (r.get("permissions") or {}).get("push") and not r.get("archived")]
            self.state["repos_etag"] = etag
        return self.state["repos"]

    def _verdict(self, repo, path, entry):
        key = f"{entry['sha']}|{path}"
        cached = self.state["blob_verdicts"].get(key)
        if cached is not None:
            return [Hit.from_list(x) for x in cached]
        data = None
        if self.det.wants_content(path) and (entry.get("size") or 0) <= self.det.max_bytes:
            if self.budget <= 0 or (self.gh.remaining is not None and self.gh.remaining < MIN_RATE_LEFT):
                raise _OutOfBudget()
            self.budget -= 1
            data = self.gh.blob(repo, entry["sha"])
        hits = self.det.check(path, data)
        self.state["blob_verdicts"][key] = [h.as_list() for h in hits]
        return hits

    def scan_branch(self, repo, branch, sha):
        """Scan the whole tree at this commit. Returns the list of infected files."""
        _, tree, _ = self.gh.request("GET", f"/repos/{repo}/git/trees/{sha}?recursive=1")
        files = []
        for e in tree.get("tree", []):
            if e.get("type") != "blob":
                continue
            path = e["path"]
            if any(part in self.det.skip_dirs for part in path.split("/")[:-1]):
                continue
            hits = self._verdict(repo, path, e)
            if hits:
                files.append({"path": path, "blob": e["sha"], "hits": [h.as_list() for h in hits],
                              "severity": worst(hits)})
        return files, bool(tree.get("truncated"))

    def run(self):
        """One full check. Returns a summary dict; state is updated in place (caller saves it)."""
        st = self.state
        before = finding_ids(st["findings"])
        repos = self.repos()
        live, incomplete, errors, scanned = set(), False, [], 0
        for i, r in enumerate(repos):
            name = r["full_name"]
            self.progress(f"Checking {name} ({i + 1}/{len(repos)})")
            try:
                _, branches, _ = self.gh.pages(f"/repos/{name}/branches?per_page=100")
            except GitHubError as e:
                if e.status in (404, 409):  # empty repo or gone
                    continue
                raise
            for b in branches:
                key = f"{name}:{b['name']}"
                live.add(key)
                sha = b["commit"]["sha"]
                if st["heads"].get(key) == sha:
                    continue
                try:
                    files, truncated = self.scan_branch(name, b["name"], sha)
                except _OutOfBudget:
                    incomplete = True
                    break
                except GitHubError as e:
                    if e.status == 0:
                        raise
                    errors.append(f"{key}: {e}")
                    continue
                scanned += 1
                if truncated:
                    errors.append(f"{key}: repository too large, only part of it was checked")
                if files:
                    st["findings"][key] = files
                else:
                    st["findings"].pop(key, None)
                st["heads"][key] = sha
            if incomplete:
                break
        if not incomplete:  # forget branches that were deleted
            for key in list(st["heads"]):
                if key not in live:
                    st["heads"].pop(key, None)
                    st["findings"].pop(key, None)
        st["last_check"] = time.time()
        st["last_error"] = None
        new = sorted(finding_ids(st["findings"]) - before)
        return {"repos": len(repos), "branches_scanned": scanned, "incomplete": incomplete, "errors": errors,
                "new": new, "api_calls": self.gh.calls, "rate_remaining": self.gh.remaining}


class _OutOfBudget(Exception):
    pass


def summarize(findings):
    """{'danger': n, 'review': n, 'branches': n} over all findings."""
    out = {"danger": 0, "review": 0, "branches": 0}
    for files in findings.values():
        if files:
            out["branches"] += 1
        for f in files:
            out[f["severity"]] += 1
    return out


def branch_url(key, path=None):
    repo, branch = key.split(":", 1)
    q = urllib.parse.quote
    if path:
        return f"https://github.com/{repo}/blob/{q(branch)}/{q(path)}"
    return f"https://github.com/{repo}/tree/{q(branch)}"
