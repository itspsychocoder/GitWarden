"""Shared test helpers. The 'malware' is harmless look-alike text, assembled at runtime so that this
file itself never matches GitWarden's rules."""
import base64
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

PAD = " " * 150
LOADER = "var z = '-67" + "52-3';"
NPM_LOADER = '{"name":"x","scripts":{"dev":"node ' + 'init && next dev","build":"next build"}}\n'

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def git(cwd, *args, data=None, env=None):
    p = subprocess.run(["git", *args], cwd=cwd, input=data, capture_output=True, env={**GIT_ENV, **(env or {})})
    if p.returncode:
        raise AssertionError(f"git {' '.join(args)}: {p.stderr.decode()}")
    return p.stdout


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf8", newline="\n") as fh:
        fh.write(text)


def clean_project(d):
    write(d, "postcss.config.mjs", "export default { plugins: {} };\n")
    write(d, "package.json", '{"name":"x","scripts":{"dev":"next dev","build":"next build"}}\n')
    write(d, ".gitignore", "node_modules\n")
    write(d, "src/a.js", "export const a = 1;\n")


def infect(d):
    """The worm's typical changes, as harmless look-alikes."""
    write(d, "postcss.config.mjs", "export default { plugins: {} };" + PAD + LOADER + "\n")
    write(d, "package.json", NPM_LOADER)
    write(d, ".gitignore", "node_modules\nconfig.bat\n")
    write(d, "init", "x" + PAD + LOADER + "\n")


class FakeRemote:
    """A local bare repo plus a working clone, standing in for one GitHub repo."""

    def __init__(self, root, full_name):
        self.full_name = full_name
        self.bare = os.path.join(root, full_name.replace("/", "__") + ".git")
        self.work = os.path.join(root, full_name.replace("/", "__") + "-work")
        git(root, "init", "-q", "--bare", "-b", "main", self.bare)
        git(root, "clone", "-q", self.bare, self.work)
        clean_project(self.work)
        self.commit("first")

    def commit(self, msg, branch="main"):
        git(self.work, "checkout", "-q", "-B", branch)
        git(self.work, "add", "-A")
        git(self.work, "commit", "-q", "--allow-empty", "-m", msg)
        git(self.work, "push", "-q", "-f", "origin", branch)


READ_TOKENS = {"test-token", "fix-token"}
WRITE_TOKENS = {"fix-token"}


class MockGitHub:
    """Just enough of the GitHub REST API, served from FakeRemote bare repos.
    test-token can only read (like the watch token); fix-token can also write."""

    def __init__(self):
        self.remotes = {}
        self.calls = []
        self.protected = {}   # "owner/repo:branch" -> "ruleset" | "protection" | "allowed"
        self.codeload_auth = []  # Authorization headers seen by the download server (must stay empty)
        self.not_modified = 0
        mock = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body, headers=None):
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-RateLimit-Remaining", "4999")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def token(self):
                return (self.headers.get("Authorization") or "").removeprefix("Bearer ")

            def body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def route(self):
                u = urlparse(self.path)
                mock.calls.append(f"{self.command} {u.path}")
                parts = [unquote(x) for x in u.path.strip("/").split("/")]
                r = mock.remotes.get(f"{parts[1]}/{parts[2]}") if parts[0] == "repos" and len(parts) > 3 else None
                return u, parts, r

            def do_GET(self):
                u, parts, r = self.route()
                if parts[0] == "_codeload":  # the download server: no token expected (or allowed)
                    mock.codeload_auth.append(self.headers.get("Authorization"))
                    rr = mock.remotes.get(f"{parts[1]}/{parts[2]}")
                    data = git(rr.bare, "archive", "--format=tar.gz", f"--prefix={parts[1]}-{parts[2]}-x/", parts[3])
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-gzip")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                if self.token() not in READ_TOKENS:
                    return self.send(401, {"message": "Bad credentials"})
                if u.path == "/user/repos":
                    listing = [(n, mock.pushed_at(n)) for n in sorted(mock.remotes)]
                    etag = '"' + str(abs(hash(str(listing)))) + '"'
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self.send(200, [{"full_name": n, "default_branch": "main", "private": True,
                                            "permissions": {"push": True}, "archived": False, "pushed_at": p}
                                           for n, p in listing], {"ETag": etag})
                if not r:
                    return self.send(404, {"message": "Not Found"})
                key = lambda b: f"{r.full_name}:{b}"  # noqa: E731
                if parts[3] == "branches" and len(parts) == 4:
                    out = git(r.bare, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads").decode()
                    etag = '"' + str(abs(hash(out))) + '"'
                    if self.headers.get("If-None-Match") == etag:
                        mock.not_modified += 1
                        self.send_response(304)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self.send(200, [{"name": n, "commit": {"sha": s}}
                                           for n, s in (l.split() for l in out.splitlines())], {"ETag": etag})
                if parts[3] == "branches":
                    tail = parts[4:]
                    want_protection = tail[-1] == "protection" and len(tail) > 1
                    branch = "/".join(tail[:-1] if want_protection else tail)
                    p = mock.protected.get(key(branch))
                    if want_protection:
                        if not p:
                            return self.send(404, {"message": "Branch not protected"})
                        return self.send(200, {"allow_force_pushes": {"enabled": p == "allowed"}})
                    sha = git(r.bare, "rev-parse", "refs/heads/" + branch).decode().strip()
                    return self.send(200, {"name": branch, "commit": {"sha": sha},
                                           "protected": p in ("protection", "allowed")})
                if parts[3:5] == ["rules", "branches"]:
                    branch = "/".join(parts[5:])
                    rules = [{"type": "non_fast_forward"}] if mock.protected.get(key(branch)) == "ruleset" else []
                    return self.send(200, rules)
                if parts[3] == "tarball":
                    self.send_response(302)
                    self.send_header("Location", f"{mock.url}/_codeload/{parts[1]}/{parts[2]}/{parts[4]}?token=tmp")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if parts[3:5] == ["git", "trees"]:
                    out = git(r.bare, "ls-tree", "-r", "-l", parts[5]).decode()
                    tree = []
                    for line in out.splitlines():
                        meta, path = line.split("\t", 1)
                        mode, typ, sha, size = meta.split()
                        tree.append({"path": path, "mode": mode, "type": typ, "sha": sha, "size": int(size)})
                    return self.send(200, {"sha": parts[5], "tree": tree, "truncated": False})
                if parts[3:5] == ["git", "blobs"]:
                    data = git(r.bare, "cat-file", "blob", parts[5])
                    return self.send(200, {"content": base64.b64encode(data).decode(), "encoding": "base64"})
                if parts[3:5] == ["git", "commits"]:
                    tree = git(r.bare, "rev-parse", parts[5] + "^{tree}").decode().strip()
                    return self.send(200, {"sha": parts[5], "tree": {"sha": tree}})
                return self.send(404, {"message": "Not Found"})

            def write_ok(self):
                if self.token() in WRITE_TOKENS:
                    return True
                code = 401 if self.token() not in READ_TOKENS else 403
                self.send(code, {"message": "Resource not accessible by personal access token"})
                return False

            def do_POST(self):
                u, parts, r = self.route()
                if not self.write_ok():
                    return
                if not r:
                    return self.send(404, {"message": "Not Found"})
                b = self.body()
                if parts[3:5] == ["git", "blobs"]:
                    sha = git(r.bare, "hash-object", "-w", "--stdin", data=base64.b64decode(b["content"])).decode().strip()
                    return self.send(201, {"sha": sha})
                if parts[3:5] == ["git", "trees"]:
                    idx = r.bare + ".index"
                    env = {"GIT_INDEX_FILE": idx}
                    git(r.bare, "read-tree", b["base_tree"], env=env)
                    info = "".join(f"0 {'0' * 40}\t{e['path']}\n" if e["sha"] is None
                                   else f"{e['mode']} {e['sha']}\t{e['path']}\n" for e in b["tree"])
                    git(r.bare, "update-index", "--index-info", data=info.encode(), env=env)
                    sha = git(r.bare, "write-tree", env=env).decode().strip()
                    os.remove(idx)
                    return self.send(201, {"sha": sha})
                if parts[3:5] == ["git", "commits"]:
                    args = ["commit-tree", b["tree"]]
                    for p in b["parents"]:
                        args += ["-p", p]
                    sha = git(r.bare, *args, "-F", "-", data=b["message"].encode()).decode().strip()
                    return self.send(201, {"sha": sha})
                return self.send(404, {"message": "Not Found"})

            def do_PATCH(self):
                u, parts, r = self.route()
                if not self.write_ok():
                    return
                b = self.body()
                if r and parts[3:6] == ["git", "refs", "heads"]:
                    ref = "refs/heads/" + "/".join(parts[6:])
                    old = git(r.bare, "rev-parse", ref).decode().strip()
                    ff = subprocess.run(["git", "-C", r.bare, "merge-base", "--is-ancestor", old, b["sha"]], env=GIT_ENV)
                    if ff.returncode and not b.get("force"):
                        return self.send(422, {"message": "Update is not a fast forward"})
                    git(r.bare, "update-ref", ref, b["sha"], old)
                    return self.send(200, {"ref": ref, "object": {"sha": b["sha"]}})
                return self.send(404, {"message": "Not Found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def pushed_at(self, name):
        """Like GitHub's pushed_at: changes whenever any branch or tag moves."""
        return str(abs(hash(git(self.remotes[name].bare, "for-each-ref").decode())))

    def branch_list_calls(self):
        return sum(1 for c in self.calls if c.startswith("GET ") and c.endswith("/branches"))

    def add(self, root, full_name):
        self.remotes[full_name] = FakeRemote(root, full_name)
        return self.remotes[full_name]

    def blob_calls(self):
        return sum(1 for c in self.calls if "/git/blobs/" in c)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def tmpdir():
    return tempfile.TemporaryDirectory(prefix="rg-test-")
