"""Malware detection for one file version. Pure data in, findings out: nothing scanned is ever run."""
import json
import os
import re
from dataclasses import dataclass

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")
DANGER, REVIEW = "danger", "review"


@dataclass(frozen=True)
class Hit:
    rule: str
    severity: str
    label: str

    def as_list(self):
        return [self.rule, self.severity, self.label]

    @classmethod
    def from_list(cls, x):
        return cls(*x)


class Detector:
    def __init__(self, rules_file=RULES_FILE):
        with open(rules_file, encoding="utf8") as fh:
            r = json.load(fh)
        self.max_bytes = r["max_file_bytes"]
        self.skip_dirs = set(r["skip_dirs"])
        self.skip_content = re.compile(r["skip_content"])
        self.vendored = re.compile(r["vendored"])
        self.code = re.compile(r["code_files"])
        self.media = re.compile(r["media_files"], re.I)
        self.path_rules = [(Hit(x["id"], x["severity"], x["label"]), re.compile(x["pattern"])) for x in r["path_rules"]]
        self.content_rules = [(Hit(x["id"], x["severity"], x["label"]), x["scope"], x.get("min_count", 1),
                               re.compile(x["pattern"].encode(), re.M)) for x in r["content_rules"]]
        fm = r["fake_media"]
        self.fake_media = (Hit(fm["id"], fm["severity"], fm["label"]), re.compile(fm["pattern"].encode()))

    # ------------------------------------------------------------------ helpers
    def wants_content(self, path):
        """Is this file worth downloading/reading? (Everything else is checked by name only.)"""
        base = os.path.basename(path)
        return bool(self.code.search(path) or self.media.search(path) or base in (".gitignore", "package.json")
                    or "/.vscode/" in "/" + path)

    def _scope_ok(self, scope, path):
        base = os.path.basename(path)
        if scope == "any":
            return True
        if scope == "vscode":
            return "/.vscode/" in "/" + path
        if scope == "gitignore":
            return base == ".gitignore"
        if scope == "package_json":
            return base == "package.json"
        if scope == "code":
            return bool(self.code.search(path)) and not self.vendored.search(path)
        return False

    # ------------------------------------------------------------------ checks
    def check_path(self, path):
        return [hit for hit, rx in self.path_rules if rx.search(path)]

    def check_content(self, path, data):
        if data is None or self.skip_content.search(path) or len(data) > self.max_bytes:
            return []
        head = data[:8000]
        if self.media.search(path):
            hit, rx = self.fake_media
            return [hit] if rx.search(head) else []
        if b"\0" in head:  # real binary file
            return []
        hits = []
        for hit, scope, min_count, rx in self.content_rules:
            if not self._scope_ok(scope, path):
                continue
            if min_count > 1:
                if len(rx.findall(data)) >= min_count:
                    hits.append(hit)
            elif rx.search(data):
                hits.append(hit)
        return hits

    def check(self, path, data):
        """All hits for one file version (data may be None: name-only check). Deduplicated by rule."""
        seen, out = set(), []
        for h in self.check_path(path) + self.check_content(path, data):
            if h.rule not in seen:
                seen.add(h.rule)
                out.append(h)
        return out


def worst(hits):
    return DANGER if any(h.severity == DANGER for h in hits) else (REVIEW if hits else None)
