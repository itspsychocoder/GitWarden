"""Scan the git objects a fetch/clone/pull is about to bring in, before git points any branch at them.

Called by the reference-transaction hook (see githooks/) with the incoming commit IDs:
    python3 -I gitscan.py --incoming <sha> [<sha> ...]
Only objects that no existing ref already reaches are read, so a fetch costs as much as what it downloads.
Reads git objects as data; never checks out or runs anything. Exit 0 clean, 1 malware, 2 couldn't scan.
"""
import argparse
import os
import subprocess
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from gitwarden.detect import DANGER, Detector  # noqa: E402


def git(*args, data=None):
    return subprocess.run(["git", *args], input=data, capture_output=True)


def new_blobs(tips, everything=False):
    """[(sha, path)] for blobs reachable from tips but from no existing ref (or all of them)."""
    args = ["rev-list", "--objects", *tips]
    if not everything:
        args += ["--not", "--all"]
    p = git(*args)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf8", "replace").strip())
    out = []
    for line in p.stdout.decode("utf8", "surrogateescape").splitlines():
        sha, _, path = line.partition(" ")
        if path:
            out.append((sha, path))
    return out


def read_objects(shas, max_bytes, wanted):
    """{sha: bytes or None} for every blob among shas (trees and commits are left out).
    Content is read only for shas in `wanted` that fit in max_bytes; other blobs map to None."""
    if not shas:
        return {}
    p = git("cat-file", "--batch-check", data="\n".join(shas).encode())
    sizes = {}
    for line in p.stdout.decode().splitlines():
        f = line.split()
        if len(f) == 3 and f[1] == "blob":
            sizes[f[0]] = int(f[2])
    data = {s: None for s in sizes}
    read = [s for s, n in sizes.items() if s in wanted and n <= max_bytes]
    if read:
        out = git("cat-file", "--batch", data="\n".join(read).encode()).stdout
        i = 0
        while i < len(out):
            nl = out.index(b"\n", i)
            head = out[i:nl].split()
            size = int(head[2])
            data[head[0].decode()] = out[nl + 1:nl + 1 + size]
            i = nl + 2 + size
    return data


def scan(tips, everything=False, det=None):
    """[(path, [labels])] for dangerous files among the incoming objects."""
    det = det or Detector()
    items = [(s, p) for s, p in new_blobs(tips, everything)
             if not any(part in det.skip_dirs for part in p.split("/")[:-1])]
    wanted = {s for s, p in items if det.wants_content(p)}
    blobs = read_objects(sorted({s for s, _ in items}), det.max_bytes, wanted)
    found = {}
    for sha, path in items:
        if sha not in blobs:
            continue  # a directory (tree), not a file
        hits = [h for h in det.check(path, blobs[sha]) if h.severity == DANGER]
        if hits:
            found.setdefault(path, set()).update(h.label for h in hits)
    return sorted((p, sorted(labels)) for p, labels in found.items())


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--incoming", nargs="+", required=True, help="commit IDs a ref update would point to")
    ap.add_argument("--all", action="store_true", help="scan everything reachable, not only new objects")
    a = ap.parse_args(argv)
    try:
        found = scan(a.incoming, everything=a.all)
    except Exception as e:  # never block a fetch because GitWarden itself broke
        print(f"GitWarden: couldn't scan the incoming code ({e}); letting it through.", file=sys.stderr)
        return 2
    if not found:
        return 0
    print("\nGitWarden: MALWARE in the incoming code. Nothing was changed.", file=sys.stderr)
    for path, labels in found[:20]:
        print(f"  {path}  ({', '.join(labels)})", file=sys.stderr)
    if len(found) > 20:
        print(f"  … and {len(found) - 20} more files", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
