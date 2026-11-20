"""Decide how to clean one infected file version: delete it, cut the injected code out, or leave it for you.

Pure function of (path, bytes). Used by both the cleanup commit and the history rewrite, so a file gets the
same treatment everywhere. An edit is only accepted when the result has no dangerous hits left.
"""
import json
import os
import re
from dataclasses import dataclass, field

from .detect import DANGER

KEEP, EDIT, DELETE, MANUAL = "keep", "edit", "delete", "manual"

# Files the worm creates outright: removing the whole file is the fix.
WHOLE_FILE_RULES = {"orc_file", "dropper_file", "fake_media"}
OFFSCREEN_LINE = re.compile(r"^(.*?\S)([ \t]{100,})(\S.*)$")
GITIGNORE_MARKER = re.compile(r"^(?:config\.bat|temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)\s*$")
NPM_PREFIX = re.compile(r"node\s+(?:\./)?init\b\s*(?:&&|;)\s*")
NPM_SUFFIX = re.compile(r"\s*(?:&&|;)\s*node\s+(?:\./)?init\b")
NPM_ONLY = re.compile(r',?\s*"[\w:.-]+"\s*:\s*"node\s+(?:\./)?init\b[^"]*"')


@dataclass
class Plan:
    action: str                       # keep | edit | delete | manual
    new: bytes | None = None          # new content for edit
    rules: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def _danger(det, path, data):
    return [h for h in det.check(path, data) if h.severity == DANGER]


def clean(det, path, data):
    hits = _danger(det, path, data)
    if not hits:
        return Plan(KEEP)
    rules = sorted({h.rule for h in hits})
    if WHOLE_FILE_RULES & set(rules) or os.path.basename(path) == "init" or data is None:
        return Plan(DELETE, rules=rules, notes=["file added by the malware"])
    try:
        text = data.decode("utf8")
    except UnicodeDecodeError:
        return Plan(MANUAL, rules=rules, notes=["not a text file"])

    notes = []
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(newline)

    if "offscreen" in rules:
        out = []
        for i, line in enumerate(lines, 1):
            m = OFFSCREEN_LINE.match(line)
            if m:
                out.append(m.group(1))
                notes.append(f"line {i}: cut {len(m.group(3))} characters hidden off-screen")
            else:
                out.append(line)
        lines = out

    if "gitignore_marker" in rules:
        kept = [x for x in lines if not GITIGNORE_MARKER.match(x)]
        if len(kept) != len(lines):
            notes.append(f"removed {len(lines) - len(kept)} malware marker line(s)")
        lines = kept

    text2 = newline.join(lines)

    if "npm_loader" in rules:
        t = NPM_SUFFIX.sub("", NPM_PREFIX.sub("", text2))
        t = NPM_ONLY.sub("", t)
        if t != text2:
            notes.append("removed 'node init' from npm scripts")
            text2 = t

    if "autorun" in rules:
        t = _strip_autorun(text2)
        if t is None:
            return Plan(MANUAL, rules=rules, notes=notes + ["VS Code file isn't plain JSON; edit it by hand"])
        if t == "":
            return Plan(DELETE, rules=rules, notes=notes + ["only contained auto-run tasks"])
        notes.append("removed tasks that run when the folder opens")
        text2 = t

    new = text2.encode("utf8")
    if new == data:
        return Plan(MANUAL, rules=rules, notes=["no automatic fix for this kind of code"])
    if not new.strip():
        return Plan(DELETE, rules=rules, notes=notes + ["nothing left after cleaning"])
    left = _danger(det, path, new)
    if left:
        return Plan(MANUAL, rules=rules, notes=notes + [f"still matches after cleaning: {', '.join(sorted({h.label for h in left}))}"])
    return Plan(EDIT, new=new, rules=rules, notes=notes)


def _strip_autorun(text):
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    changed = False
    if isinstance(doc.get("tasks"), list):
        keep = [t for t in doc["tasks"] if not (isinstance(t, dict) and (t.get("runOptions") or {}).get("runOn") == "folderOpen")]
        changed = len(keep) != len(doc["tasks"])
        doc["tasks"] = keep
        if not keep and set(doc) <= {"version", "tasks"}:
            return ""
    for k in ("task.allowAutomaticTasks",):
        if k in doc:
            doc.pop(k)
            changed = True
    if not changed:
        return None
    return json.dumps(doc, indent=2) + "\n"
