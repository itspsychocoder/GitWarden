"""Git protection: global git hooks that cancel a fetch, pull or clone when the incoming code has malware.

`on` writes hooks into ~/.local/share/gitwarden/githooks and points git's global core.hooksPath at them.
Because a global hooks folder hides each repo's own .git/hooks, every hook here also runs the repo's own
hook of the same name, so Git LFS, pre-commit and the like keep working.

Limits: a repo that sets its own core.hooksPath (husky, for example) uses that instead, so it isn't
protected; and `git fetch origin x:y` straight into a local branch isn't checked (it looks exactly like a
local commit to the hook).
"""
import os
import shlex
import shutil
import subprocess
import sys

from . import config

HERE = os.path.dirname(os.path.abspath(__file__))
MARKER = "# GitWarden git protection"

# Every hook git knows; all of them pass through to the repo's own hook.
ALL_HOOKS = [
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
    "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
    "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
    "fsmonitor-watchman", "post-index-change", "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit",
]

PASS_THROUGH = f"""#!/bin/sh
{MARKER}: runs this repo's own hook of the same name, as git would without GitWarden.
own="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/$(basename "$0")"
[ -x "$own" ] && exec "$own" "$@"
exit 0
"""

REFERENCE_TRANSACTION = f"""#!/bin/sh
{MARKER}: checks what a fetch, pull or clone brings in, before any branch moves to it.
# Exiting non-zero while the update is "prepared" cancels it, so your files never change.
# Let one command through on purpose (e.g. to clone an infected repo to clean it):
#   GITWARDEN_ALLOW_FETCH=1 git ...
input=$(cat)
own="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/reference-transaction"
run_own() {{ [ -x "$own" ] || return 0; printf '%s\\n' "$input" | "$own" "$@"; }}
if [ "$1" != prepared ] || [ -n "$GITWARDEN_ALLOW_FETCH" ]; then
  run_own "$@"
  exit $?
fi
tips=""
zero=0000000000000000000000000000000000000000
while read -r old new ref; do
  case "$ref" in refs/remotes/*|refs/tags/*) ;; *) continue ;; esac
  case "$new" in ""|ref:*) continue ;; esac          # symbolic ref, e.g. origin/HEAD
  case "$new" in *[!0]*) ;; *) continue ;; esac       # all zeros: a deletion
  [ "$old" = "$new" ] && continue
  # Anything new at all? (nothing new for e.g. a remote branch moving to a commit you already have)
  [ -n "$(git rev-list -n 1 "$new" --not --all 2>/dev/null)" ] || continue
  tips="$tips $new"
done <<EOF
$input
EOF
if [ -n "$tips" ]; then
  {{PYTHON}} -I {{GITSCAN}} --incoming $tips
  status=$?
  if [ "$status" -eq 1 ]; then
    {{
      echo "GitWarden: this fetch/pull/clone was cancelled. Your files and branches were not changed."
      echo "Tell whoever pushed it that their machine is infected. To fetch it anyway (to clean it):"
      echo "  GITWARDEN_ALLOW_FETCH=1 git <your command>"
    }} >&2
    command -v notify-send >/dev/null 2>&1 && \\
      notify-send -u critical -a GitWarden "Git pull blocked: malware" \\
      "Incoming code in $(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)") has malware. Nothing was changed." \\
      >/dev/null 2>&1 &
    exit 1
  fi
fi
run_own "$@"
"""


def hooks_dir():
    d = os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "gitwarden", "githooks")
    return os.environ.get("GITWARDEN_HOOKS_DIR") or d


def _git(*args):
    git = shutil.which("git")
    if not git:
        return 127, "", "Git isn't installed."
    p = subprocess.run([git, *args], capture_output=True, text=True, cwd=os.path.expanduser("~"))
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def current():
    rc, out, _ = _git("config", "--global", "--get", "core.hooksPath")
    return out if rc == 0 else ""


def _same(a, b):
    return bool(a and b) and os.path.realpath(os.path.expanduser(a)) == os.path.realpath(b)


def status():
    """'on', 'off', 'other' (core.hooksPath points somewhere else) or 'nogit'."""
    if not shutil.which("git"):
        return "nogit"
    cur = current()
    if not cur:
        return "off"
    if not _same(cur, hooks_dir()):
        return "other"
    ok = os.path.exists(os.path.join(hooks_dir(), "reference-transaction"))
    return "on" if ok else "off"


def write_hooks(d):
    os.makedirs(d, mode=0o700, exist_ok=True)
    gitscan = os.path.join(HERE, "gitscan.py")
    body = (REFERENCE_TRANSACTION.replace("{PYTHON}", shlex.quote(sys.executable))
            .replace("{GITSCAN}", shlex.quote(gitscan)))
    for name in ALL_HOOKS:
        path = os.path.join(d, name)
        with open(path + ".tmp", "w", encoding="utf8", newline="\n") as fh:
            fh.write(body if name == "reference-transaction" else PASS_THROUGH)
        os.chmod(path + ".tmp", 0o755)
        os.replace(path + ".tmp", path)


def install(force=False):
    """Returns (ok, message)."""
    cur = current()
    if cur and not _same(cur, hooks_dir()) and not force:
        return False, (f"Git already uses hooks from {cur} for every repo. Turning GitWarden's protection on "
                       "would replace that setting.")
    write_hooks(hooks_dir())
    rc, _, err = _git("config", "--global", "core.hooksPath", hooks_dir())
    if rc:
        return False, err or "git config failed"
    config.log(f"git protection on (core.hooksPath={hooks_dir()}; was {cur or 'unset'})")
    return True, "Git protection is on: fetches, pulls and clones that bring malware are cancelled."


def uninstall():
    if _same(current(), hooks_dir()):
        _git("config", "--global", "--unset", "core.hooksPath")
        config.log("git protection off")
    return True, "Git protection is off."


def refresh():
    """Rewrite the hooks if protection is on (e.g. after GitWarden moved or was updated)."""
    if status() == "on":
        write_hooks(hooks_dir())
