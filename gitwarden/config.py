"""Where GitWarden keeps its settings and state (XDG folders), and the GitHub token."""
import json
import os
import shutil
import subprocess

APP_ID = "io.github.itspsychocoder.GitWarden"
APP_NAME = "GitWarden"


def _xdg(var, default):
    d = os.path.join(os.environ.get(var) or os.path.expanduser(default), "gitwarden")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def config_dir():
    return os.environ.get("GITWARDEN_CONFIG") or _xdg("XDG_CONFIG_HOME", "~/.config")


def state_dir():
    return os.environ.get("GITWARDEN_STATE") or _xdg("XDG_STATE_HOME", "~/.local/state")


def _write_private(path, text):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def load_json(path, default):
    try:
        with open(path, encoding="utf8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _write_private(path, json.dumps(data, indent=1, sort_keys=True))


# ---------------------------------------------------------------- settings

DEFAULTS = {"interval_minutes": 10, "paused": False, "notify": True}


def settings_path():
    return os.path.join(config_dir(), "settings.json")


def load_settings():
    return {**DEFAULTS, **load_json(settings_path(), {})}


def save_settings(s):
    save_json(settings_path(), s)


# ---------------------------------------------------------------- GitHub token

def token_path():
    return os.path.join(config_dir(), "github-token")


def log(msg):
    """Append one line to ~/.local/state/gitwarden/gitwarden.log (never logs token values)."""
    import time
    try:
        with open(os.path.join(state_dir(), "gitwarden.log"), "a", encoding="utf8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def save_token(token):
    _write_private(token_path(), token.strip() + "\n")
    log("watch token saved")


def forget_token(reason="Forget saved token pressed"):
    try:
        os.remove(token_path())
        log(f"watch token removed ({reason})")
    except FileNotFoundError:
        pass


def github_token():
    """(token, source) or (None, reason). Order: env var, saved token, GitHub CLI login."""
    if os.environ.get("GITWARDEN_GITHUB_TOKEN"):
        return os.environ["GITWARDEN_GITHUB_TOKEN"], "environment"
    try:
        with open(token_path(), encoding="utf8") as fh:
            t = fh.read().strip()
        if t:
            return t, "saved token"
    except OSError:
        pass
    gh = shutil.which("gh")
    if gh:
        try:
            p = subprocess.run([gh, "auth", "token"], capture_output=True, text=True, timeout=30,
                               cwd=os.path.expanduser("~"))
            if p.returncode == 0 and p.stdout.strip():
                return p.stdout.strip(), "GitHub CLI"
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None, "Not signed in to the GitHub CLI (run: gh auth login), and no token saved."
    return None, "No GitHub token yet. Paste a token in GitWarden, or install the GitHub CLI and run: gh auth login"
