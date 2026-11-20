"""RepoGuard for Linux: top-bar status icon + window (GTK 4 / libadwaita)."""
import copy
import os
import sys
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

try:
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify  # noqa: E402
except (ValueError, ImportError):
    Notify = None

from . import autostart, config, github  # noqa: E402
from .tray import Tray  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ICON_DIR = os.path.join(HERE, "icons")
STATUS_ICONS = os.path.join(ICON_DIR, "hicolor", "scalable", "status")


def ago(ts):
    if not ts:
        return "never"
    s = int(time.time() - ts)
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return time.strftime("%d %b %H:%M", time.localtime(ts))


def open_url(url):
    try:
        Gio.AppInfo.launch_default_for_uri(url, None)
    except GLib.Error as e:
        print("RepoGuard: could not open", url, e.message, file=sys.stderr)


# ====================================================================== controller

class Controller:
    """Owns the state, runs checks in a worker thread, and keeps the icon, menu and window in sync."""

    def __init__(self, app):
        self.app = app
        self.settings = config.load_settings()
        self.state = github.load_state()
        self.state.setdefault("alerted", [])
        self.checking = False
        self.progress = ""
        self.token_problem = None
        self.listeners = []
        self.tray = None
        self._timer = None
        self._notes = []

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        if Tray.available():
            self.tray = Tray(config.APP_ID, config.APP_NAME, ICON_DIR, on_activate=self.app.show_window)
        else:
            print("RepoGuard: no top-bar icon host found (enable the 'Ubuntu AppIndicators' or "
                  "'AppIndicator and KStatusNotifierItem Support' GNOME extension).", file=sys.stderr)
        if Notify:
            Notify.init(config.APP_NAME)
        token, why = config.github_token()
        self.token_problem = None if token else why
        self.refresh()
        GLib.timeout_add_seconds(5, lambda: (self._auto(), False)[1])
        self.reschedule()
        GLib.timeout_add_seconds(30, lambda: (self.refresh(), True)[1])  # keeps "checked X min ago" fresh

    def reschedule(self):
        if self._timer:
            GLib.source_remove(self._timer)
        minutes = max(1, int(self.settings.get("interval_minutes", 10)))
        self._timer = GLib.timeout_add_seconds(minutes * 60, lambda: (self._auto(), True)[1])

    def _auto(self):
        if not self.settings.get("paused"):
            self.check_now()

    def save_settings(self):
        config.save_settings(self.settings)

    # ---------------------------------------------------------------- checks
    def check_now(self):
        if self.checking:
            return
        token, why = config.github_token()
        if not token:
            self.token_problem = why
            self.refresh()
            return
        self.token_problem = None
        self.checking, self.progress = True, "Starting…"
        self.refresh()
        work_state = copy.deepcopy(self.state)

        def work():
            err = result = None
            try:
                gh = github.GitHub(token)
                watcher = github.Watcher(gh, work_state, progress=lambda m: GLib.idle_add(self._set_progress, m),
                                         checkpoint=lambda: github.save_state(work_state))
                result = watcher.run()
            except github.GitHubError as e:
                err = ("GitHub rejected the token. Paste a new one in Settings." if e.status == 401 else str(e))
            except Exception as e:  # keep the app alive whatever happens
                err = f"Unexpected error: {e!r}"
            GLib.idle_add(self._done, work_state, result, err)

        threading.Thread(target=work, name="repoguard-check", daemon=True).start()

    def _set_progress(self, msg):
        self.progress = msg
        self.refresh()
        return False

    def _done(self, new_state, result, err):
        self.checking, self.progress = False, ""
        new_state["last_error"] = err
        if result and result.get("errors"):
            new_state["last_warnings"] = result["errors"][:20]
        self.state = new_state
        current = github.finding_ids(self.state["findings"], danger_only=True)  # review notes never pop up
        fresh = sorted(current - set(self.state.get("alerted", [])))
        self.state["alerted"] = sorted(current)
        github.save_state(self.state)
        if fresh:
            self.alert(fresh)
        self.refresh()
        return False

    # ---------------------------------------------------------------- alerts
    def alert(self, fresh_ids):
        branches = sorted({i.split("|", 1)[0] for i in fresh_ids})
        if not self.settings.get("notify", True):
            return
        title = "Malware pushed to GitHub" if len(branches) == 1 else f"Malware pushed to {len(branches)} GitHub branches"
        body = "\n".join(b.replace(":", " · ") for b in branches[:5]) + ("\n…" if len(branches) > 5 else "")
        body += "\nDon't pull these branches. Open RepoGuard to review."
        if Notify:
            n = Notify.Notification.new(title, body, os.path.join(STATUS_ICONS, "repoguard-alert.svg"))
            n.set_urgency(Notify.Urgency.CRITICAL)
            try:
                n.add_action("open", "Open RepoGuard", lambda *a: self.app.show_window())
            except Exception:
                pass
            n.connect("closed", lambda n: self._notes.remove(n) if n in self._notes else None)
            self._notes.append(n)
            try:
                n.show()
                return
            except GLib.Error:
                pass  # no notification daemon: the red top-bar icon is the alert

    # ---------------------------------------------------------------- derived status
    def counts(self):
        return github.summarize(self.state["findings"])

    def status(self):
        """(icon, headline, detail) for the icon, menu and window."""
        c = self.counts()
        if self.checking:
            return "repoguard-busy-symbolic", "Checking GitHub…", self.progress
        if c["danger"]:
            return ("repoguard-alert", f"Malware on {c['branches']} branch{'es' if c['branches'] != 1 else ''}",
                    f"{c['danger']} dangerous file{'s' if c['danger'] != 1 else ''}. Don't pull these branches.")
        if self.token_problem:
            return "repoguard-off-symbolic", "GitHub not connected", self.token_problem
        if self.state.get("last_error"):
            return "repoguard-off-symbolic", "Last check failed", self.state["last_error"]
        if self.settings.get("paused"):
            return "repoguard-paused-symbolic", "Watching paused", "Turn it back on from the menu."
        if not self.state.get("last_check"):
            return "repoguard-busy-symbolic", "Not checked yet", "The first check starts in a moment."
        extra = f" · {c['review']} file{'s' if c['review'] != 1 else ''} worth a look" if c["review"] else ""
        return "repoguard-ok-symbolic", "All clear", f"No malware found{extra}"

    # ---------------------------------------------------------------- UI sync
    def refresh(self):
        icon, head, detail = self.status()
        c = self.counts()
        if self.tray:
            self.tray.set_state(icon=icon, label=str(c["danger"]) if c["danger"] else "",
                                tooltip=f"{head}\n{detail}", attention=bool(c["danger"]))
            self.tray.set_menu(self.menu_items(head, detail, c))
        for fn in list(self.listeners):
            fn()

    def menu_items(self, head, detail, c):
        repos = len(self.state.get("repos", []))
        items = [{"label": head, "enabled": False},
                 {"label": detail[:70], "enabled": False, "visible": bool(detail)},
                 {"label": f"GitHub: {repos} repos · checked {ago(self.state.get('last_check'))}", "enabled": False}]
        bad = [k for k, files in sorted(self.state["findings"].items()) if any(f["severity"] == "danger" for f in files)]
        if bad:
            items.append({"separator": True})
            for key in bad[:6]:
                n = sum(1 for f in self.state["findings"][key] if f["severity"] == "danger")
                items.append({"label": f"⚠ {key.replace(':', ' · ')}  ({n})", "icon": "web-browser-symbolic",
                              "action": lambda key=key: open_url(github.branch_url(key))})
            if len(bad) > 6:
                items.append({"label": f"…and {len(bad) - 6} more", "action": self.app.show_window})
        items += [{"separator": True},
                  {"label": "Check now", "enabled": not self.checking, "action": self.check_now},
                  {"label": "Open RepoGuard…", "action": self.app.show_window},
                  {"label": "Pause watching", "toggle": "checkmark", "state": bool(self.settings.get("paused")),
                   "action": self.toggle_pause},
                  {"separator": True},
                  {"label": "Quit", "action": self.app.quit}]
        return items

    def toggle_pause(self):
        self.settings["paused"] = not self.settings.get("paused")
        self.save_settings()
        self.refresh()


# ====================================================================== window

class Window(Adw.ApplicationWindow):
    def __init__(self, app, ctl):
        super().__init__(application=app, title=config.APP_NAME, default_width=760, default_height=640)
        self.ctl = ctl
        self.set_hide_on_close(ctl.tray is not None)

        self.stack = Adw.ViewStack()
        header = Adw.HeaderBar()
        header.set_title_widget(Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE))
        self.check_btn = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Check now")
        self.check_btn.connect("clicked", lambda *_: ctl.check_now())
        header.pack_start(self.check_btn)
        self.spinner = Adw.Spinner(visible=False)
        header.pack_start(self.spinner)

        self.overview = Adw.PreferencesPage()
        self.settings_page = Adw.PreferencesPage()
        self.stack.add_titled_with_icon(self.overview, "overview", "Overview", "security-high-symbolic")
        self.stack.add_titled_with_icon(self.settings_page, "settings", "Settings", "emblem-system-symbolic")
        self._groups = []
        self._build_settings()

        self.toasts = Adw.ToastOverlay(child=self.stack)
        view = Adw.ToolbarView(content=self.toasts)
        view.add_top_bar(header)
        self.set_content(view)
        ctl.listeners.append(self.update)
        self.update()

    def toast(self, msg):
        self.toasts.add_toast(Adw.Toast(title=msg, timeout=4))

    # ---------------------------------------------------------------- overview
    def update(self):
        ctl = self.ctl
        if hasattr(self, "conn_row"):
            self._update_conn()
        self.check_btn.set_sensitive(not ctl.checking)
        self.spinner.set_visible(ctl.checking)
        for g in self._groups:
            self.overview.remove(g)
        self._groups = []
        icon, head, detail = ctl.status()

        g = self._group(None)
        row = Adw.ActionRow(title=head, subtitle=detail)
        img = Gtk.Image.new_from_file(os.path.join(STATUS_ICONS, icon + ".svg"))
        img.set_pixel_size(32)
        if icon.endswith("-symbolic"):
            img.add_css_class("dim-label")
        row.add_prefix(img)
        row.add_css_class("property")
        g.add(row)
        repos = ctl.state.get("repos", [])
        g.add(Adw.ActionRow(title="Last check", subtitle=f"{ago(ctl.state.get('last_check'))} · "
                            f"{len(repos)} repos you can push to · every {ctl.settings['interval_minutes']} min"))

        if ctl.token_problem:
            self._token_group(self._group("Connect GitHub",
                                          "RepoGuard needs read access to your repos to watch new commits."))

        findings = ctl.state["findings"]
        danger = {k: [f for f in v if f["severity"] == "danger"] for k, v in findings.items()}
        danger = {k: v for k, v in danger.items() if v}
        review = [(k, f) for k, v in sorted(findings.items()) for f in v if f["severity"] != "danger"]

        tg = self._group("Threats on GitHub", "Files that match this malware. Nothing here has been run.")
        if not danger:
            tg.add(Adw.ActionRow(title="No malware found", subtitle="Every checked branch is clean."))
        for key in sorted(danger):
            files = danger[key]
            exp = Adw.ExpanderRow(title=GLib.markup_escape_text(key.replace(":", " · ")),
                                  subtitle=f"{len(files)} dangerous file{'s' if len(files) != 1 else ''}")
            exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
            exp.add_css_class("error")
            fb = Gtk.Button(label="Fix…", valign=Gtk.Align.CENTER, tooltip_text="Remove the malware on GitHub")
            fb.add_css_class("suggested-action")
            fb.connect("clicked", lambda *_, k=key: self.open_fix(k))
            exp.add_suffix(fb)
            btn = Gtk.Button(icon_name="web-browser-symbolic", tooltip_text="Open branch on GitHub", valign=Gtk.Align.CENTER)
            btn.add_css_class("flat")
            btn.connect("clicked", lambda *_, k=key: open_url(github.branch_url(k)))
            exp.add_suffix(btn)
            for f in sorted(files, key=lambda f: f["path"]):
                exp.add_row(self._file_row(key, f, "dialog-error-symbolic"))
            tg.add(exp)

        if review:
            rg = self._group("Worth a look (not malware)",
                             "Normal files that can run code: GitHub workflows, .npmrc, npm install scripts, "
                             "VS Code tasks. Check them only if you didn't add them yourself.")
            exp = Adw.ExpanderRow(title=f"{len(review)} file{'s' if len(review) != 1 else ''} that can run code",
                                  subtitle=f"in {len({k for k, _ in review})} branches")
            exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            for key, f in review:
                exp.add_row(self._file_row(key, f, "dialog-information-symbolic", show_branch=True))
            rg.add(exp)

        warnings = ctl.state.get("last_warnings") or []
        if warnings:
            wg = self._group("Notes from the last check")
            for w in warnings:
                wg.add(Adw.ActionRow(title=GLib.markup_escape_text(w)))

        if repos:
            rg = self._group("Watched repositories")
            exp = Adw.ExpanderRow(title=f"{len(repos)} repos you can push to",
                                  subtitle="Every branch is checked; only changed files are downloaded.")
            for r in repos[:300]:
                rr = Adw.ActionRow(title=GLib.markup_escape_text(r["full_name"]),
                                   subtitle="private" if r.get("private") else "public")
                exp.add_row(rr)
            rg.add(exp)

    def _file_row(self, key, f, icon, show_branch=False):
        labels = " · ".join(dict.fromkeys(h[2] for h in f["hits"]))
        sub = f"{key.replace(':', ' · ')} — {labels}" if show_branch else labels
        r = Adw.ActionRow(title=GLib.markup_escape_text(f["path"]), subtitle=GLib.markup_escape_text(sub))
        r.add_prefix(Gtk.Image.new_from_icon_name(icon))
        ob = Gtk.Button(icon_name="adw-external-link-symbolic", tooltip_text="Open file on GitHub",
                        valign=Gtk.Align.CENTER)
        ob.add_css_class("flat")
        ob.connect("clicked", lambda *_, k=key, p=f["path"]: open_url(github.branch_url(k, p)))
        r.add_suffix(ob)
        return r

    def open_fix(self, key):
        from .fixdialog import FixDialog
        repo, branch = key.split(":", 1)
        infected = [k.split(":", 1)[1] for k, files in self.ctl.state["findings"].items()
                    if k.split(":", 1)[0] == repo and any(f["severity"] == "danger" for f in files)]
        FixDialog(self.ctl, repo, infected, preselect=branch).present(self)

    def _group(self, title, desc=None):
        g = Adw.PreferencesGroup(title=title or "", description=desc or "")
        self.overview.add(g)
        self._groups.append(g)
        return g

    def _token_group(self, g):
        entry = Adw.PasswordEntryRow(title="GitHub personal access token", show_apply_button=True)
        entry.connect("apply", self._on_token)
        g.add(entry)
        help_row = Adw.ActionRow(
            title="How to get one",
            subtitle="Fine-grained token: All repositories · Contents: Read · Metadata: Read. "
                     "Or install the GitHub CLI and run gh auth login.")
        b = Gtk.Button(label="Create token", valign=Gtk.Align.CENTER)
        b.connect("clicked", lambda *_: open_url("https://github.com/settings/personal-access-tokens/new"))
        help_row.add_suffix(b)
        g.add(help_row)

    def _on_token(self, entry):
        token = entry.get_text().strip()
        if not token:
            return
        config.save_token(token)
        entry.set_text("")
        self.toast("Token saved. Checking GitHub…")
        self.ctl.check_now()

    # ---------------------------------------------------------------- settings
    def _build_settings(self):
        ctl = self.ctl
        g = Adw.PreferencesGroup(title="Watching")
        spin = Adw.SpinRow.new_with_range(1, 1440, 1)
        spin.set_title("Check every (minutes)")
        spin.set_value(ctl.settings["interval_minutes"])

        def on_interval(row, _):
            ctl.settings["interval_minutes"] = int(row.get_value())
            ctl.save_settings()
            ctl.reschedule()
        spin.connect("notify::value", on_interval)
        g.add(spin)

        notif = Adw.SwitchRow(title="Desktop notifications", subtitle="Pop up an alert when new malware is found",
                              active=ctl.settings.get("notify", True))

        def on_notify(row, _):
            ctl.settings["notify"] = row.get_active()
            ctl.save_settings()
        notif.connect("notify::active", on_notify)
        g.add(notif)

        auto = Adw.SwitchRow(title="Start at login", subtitle="Show the RepoGuard icon in the top bar when you sign in",
                             active=autostart.enabled())
        auto.connect("notify::active", lambda row, _: autostart.set_enabled(row.get_active()))
        g.add(auto)
        self.settings_page.add(g)

        gg = Adw.PreferencesGroup(title="GitHub access")
        self.conn_row = Adw.ActionRow()
        gg.add(self.conn_row)
        self._token_group(gg)
        self.settings_page.add(gg)

        fg = Adw.PreferencesGroup()
        forget = Adw.ButtonRow(title="Forget saved token…")
        forget.add_css_class("destructive-action")
        forget.connect("activated", lambda *_: self._confirm_forget())
        fg.add(forget)
        self.settings_page.add(fg)
        self._update_conn()

    def _update_conn(self):
        token, src = config.github_token()
        self.conn_row.set_title("Connected" if token else "Not connected")
        self.conn_row.set_subtitle(GLib.markup_escape_text(f"Using {src}" if token else src))

    def _confirm_forget(self):
        d = Adw.AlertDialog(heading="Forget the saved GitHub token?",
                            body="RepoGuard stops watching GitHub until you paste a token again.")
        d.add_response("cancel", "Cancel")
        d.add_response("forget", "Forget token")
        d.set_response_appearance("forget", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("cancel")
        d.set_close_response("cancel")

        def done(_d, response):
            if response == "forget":
                config.forget_token()
                self.toast("Saved token removed.")
                self.ctl.token_problem = config.github_token()[1]
                self.ctl.refresh()
        d.connect("response", done)
        d.present(self)


# ====================================================================== application

class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=config.APP_ID, flags=Gio.ApplicationFlags.HANDLES_COMMAND_LINE)
        self.ctl = None
        self.win = None

    def do_startup(self):
        Adw.Application.do_startup(self)
        Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(ICON_DIR)
        self.hold()  # keep running in the top bar with no window open
        self.ctl = Controller(self)
        self.ctl.start()

    def do_command_line(self, cmd):
        args = cmd.get_arguments()[1:]
        if "--background" not in args or self.ctl.tray is None:
            self.show_window()
        return 0

    def show_window(self):
        if self.win is None:
            self.win = Window(self, self.ctl)
        self.win.present()
        return False


def main(argv=None):
    return App().run(argv if argv is not None else sys.argv)
