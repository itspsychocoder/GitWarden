"""Start at login: an XDG autostart entry (~/.config/autostart) that starts GitWarden in the top bar."""
import os

from . import config

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "gitwarden")


def path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "autostart", config.APP_ID + ".desktop")


def desktop_entry(extra_args=""):
    icon = os.path.join(ROOT, "gitwarden", "icons", "hicolor", "scalable", "apps", config.APP_ID + ".svg")
    return ("[Desktop Entry]\nType=Application\nName=GitWarden\n"
            "Comment=Watches your GitHub repos for the git malware worm\n"
            f"Exec=\"{LAUNCHER}\"{extra_args}\nIcon={icon}\nTerminal=false\nCategories=Development;Security;\n"
            "X-GNOME-Autostart-enabled=true\n")


def enabled():
    return os.path.exists(path())


def set_enabled(on):
    p = path()
    if on:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf8") as fh:
            fh.write(desktop_entry(" --background"))
    elif os.path.exists(p):
        os.remove(p)
