"""Shared test helpers. The 'malware' is harmless look-alike text, assembled at runtime so that this
file itself never matches RepoGuard's rules."""
import base64
import json
import os
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PAD = " " * 150
LOADER = "var z = '-67" + "52-3';"
NPM_LOADER = '{"name":"x","scripts":{"dev":"node ' + 'init && next dev","build":"next build"}}\n'

GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def git(cwd, *args, data=None):
    p = subprocess.run(["git", *args], cwd=cwd, input=data, capture_output=True, env=GIT_ENV)
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


class MockGitHub:
    """Just enough of the GitHub REST API, served from FakeRemote bare repos."""

    def __init__(self):
        self.remotes = {}
        self.calls = []
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

            def do_GET(self):
                u = urlparse(self.path)
                mock.calls.append(u.path)
                if self.headers.get("Authorization") != "Bearer test-token":
                    return self.send(401, {"message": "Bad credentials"})
                parts = u.path.strip("/").split("/")
                if u.path == "/user/repos":
                    etag = '"' + str(sorted(mock.remotes)) + '"'
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304)
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                    return self.send(200, [{"full_name": n, "default_branch": "main", "private": True,
                                            "permissions": {"push": True}, "archived": False}
                                           for n in sorted(mock.remotes)], {"ETag": etag})
                if parts[0] != "repos" or len(parts) < 4:
                    return self.send(404, {"message": "Not Found"})
                r = mock.remotes.get(f"{parts[1]}/{parts[2]}")
                if not r:
                    return self.send(404, {"message": "Not Found"})
                if parts[3] == "branches":
                    out = git(r.bare, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads").decode()
                    return self.send(200, [{"name": n, "commit": {"sha": s}}
                                           for n, s in (l.split() for l in out.splitlines())])
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
                return self.send(404, {"message": "Not Found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def add(self, root, full_name):
        self.remotes[full_name] = FakeRemote(root, full_name)
        return self.remotes[full_name]

    def blob_calls(self):
        return sum(1 for c in self.calls if "/git/blobs/" in c)

    def close(self):
        self.server.shutdown()


def tmpdir():
    return tempfile.TemporaryDirectory(prefix="rg-test-")
