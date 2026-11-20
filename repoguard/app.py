"""RepoGuard for Linux: top-bar status icon + window (GTK 4 / libadwaita)."""
import copy
import json
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

from . import autostart, config, github, local, pc, protect  # noqa: E402
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


def WHERE(where):
    """Human words for where a local finding is."""
    if where == "disk":
        return "file on disk"
    if where == "git":
        return "git settings"
    kind, _, name = where.partition(":")
    return f"in branch {name}" if kind == "branch" else f"in remote branch {name}"


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
        self.local = local.load_state()
        self.local.setdefault("alerted", [])
        self.pc = config.load_json(os.path.join(config.state_dir(), "pc.json"), {"findings": [], "alerted": []})
        self.settings.setdefault("folders", local.default_folders())
        self.settings.setdefault("local_ignore", [])
        self.checking = False
        self.progress = ""
        self.token_problem = None
        self.listeners = []
        self.tray = None
        self._timer = None
        self._notes = []

    # ---------------------------------------------------------------- lifecycle
    def start(self):
        # The icon shows up whenever a top-bar host is (or later becomes) available.
        self.tray = Tray(config.APP_ID, config.APP_NAME, ICON_DIR, on_activate=self.app.show_window)
        self.tray.on_host_change = lambda up: (self.refresh(), self.app.host_changed(up))
        if not Tray.available():
            print("RepoGuard: no top-bar icon host right now (enable the 'Ubuntu AppIndicators' or "
                  "'AppIndicator and KStatusNotifierItem Support' GNOME extension); the icon appears "
                  "as soon as it is on.", file=sys.stderr)
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
        """One check of this computer's code folders (always) and of GitHub (when connected)."""
        if self.checking:
            return
        token, why = config.github_token()
        self.token_problem = None if token else why
        self.checking, self.progress = True, "Starting…"
        self.refresh()
        gh_state = copy.deepcopy(self.state)
        local_state = copy.deepcopy(self.local)
        folders = list(self.settings.get("folders") or [])
        progress = lambda m: GLib.idle_add(self._set_progress, m)  # noqa: E731

        hooks = protect.hooks_dir()

        def work():
            gh_err = result = local_err = None
            pc_findings = None
            try:
                local.Scanner(local_state, folders, progress=progress).run()
            except Exception as e:
                local_err = f"Couldn't check this computer: {e!r}"
            try:
                progress("Checking this PC…")
                pc_findings = pc.scan(own_hooks=hooks)
            except Exception as e:
                local_err = (local_err or "") + f" Couldn't run the PC check: {e!r}"
            if token:
                try:
                    watcher = github.Watcher(github.GitHub(token), gh_state, progress=progress,
                                             checkpoint=lambda: github.save_state(gh_state))
                    result = watcher.run()
                except github.GitHubError as e:
                    gh_err = ("GitHub rejected the token. Paste a new one in Settings." if e.status == 401 else str(e))
                except Exception as e:  # keep the app alive whatever happens
                    gh_err = f"Unexpected error: {e!r}"
            GLib.idle_add(self._done, gh_state if token else None, result, gh_err, local_state, local_err, pc_findings)

        threading.Thread(target=work, name="repoguard-check", daemon=True).start()

    def _set_progress(self, msg):
        self.progress = msg
        self.refresh()
        return False

    def _done(self, gh_state, result, err, local_state, local_err, pc_findings=None):
        self.checking, self.progress = False, ""
        if pc_findings is not None:
            self.pc["findings"], self.pc["last_check"] = pc_findings, time.time()
            current = {f["id"] for f in pc_findings if f["severity"] == "danger"}
            fresh = current - set(self.pc.get("alerted", []))
            self.pc["alerted"] = sorted(current)
            config.save_json(os.path.join(config.state_dir(), "pc.json"), self.pc)
            if fresh:
                bad = [f for f in pc_findings if f["id"] in fresh]
                self._notify("Signs of malware on this PC",
                             "\n".join(f"{f['title']}: {f['label']}" for f in bad[:4])
                             + ("\n…" if len(bad) > 4 else "") + "\nOpen RepoGuard to review and fix.")
        if gh_state is not None:
            gh_state["last_error"] = err
            if result and result.get("errors"):
                gh_state["last_warnings"] = result["errors"][:20]
            self.state = gh_state
            current = github.finding_ids(self.state["findings"], danger_only=True)  # review notes never pop up
            fresh = sorted(current - set(self.state.get("alerted", [])))
            self.state["alerted"] = sorted(current)
            github.save_state(self.state)
            if fresh:
                self.alert(fresh)
        local_state["last_error"] = local_err
        self.local = local_state
        current = local.finding_ids(self.local_findings())
        fresh = sorted(current - set(self.local.get("alerted", [])))
        self.local["alerted"] = sorted(current)
        local.save_state(self.local)
        if fresh:
            self.alert_local(fresh)
        self.refresh()
        return False

    def local_findings(self, ignored=False):
        """Findings on this computer, without (or only) the folders you chose to ignore."""
        ign = set(self.settings.get("local_ignore", []))
        return {k: v for k, v in self.local.get("findings", {}).items() if (k in ign) == ignored}

    def ignore_folder(self, root, on=True):
        ign = set(self.settings.get("local_ignore", []))
        (ign.add if on else ign.discard)(root)
        self.settings["local_ignore"] = sorted(ign)
        self.save_settings()
        self.refresh()

    # ---------------------------------------------------------------- alerts
    def _notify(self, title, body):
        if not self.settings.get("notify", True) or not Notify:
            return
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
        except GLib.Error:
            pass  # no notification daemon: the red top-bar icon is the alert

    def alert(self, fresh_ids):
        branches = sorted({i.split("|", 1)[0] for i in fresh_ids})
        title = "Malware pushed to GitHub" if len(branches) == 1 else f"Malware pushed to {len(branches)} GitHub branches"
        body = "\n".join(b.replace(":", " · ") for b in branches[:5]) + ("\n…" if len(branches) > 5 else "")
        self._notify(title, body + "\nDon't pull these branches. Open RepoGuard to review.")

    def alert_local(self, fresh_ids):
        places = sorted({i.split("|", 1)[0] for i in fresh_ids})
        home = os.path.expanduser("~")
        title = "Malware on this computer" if len(places) == 1 else f"Malware in {len(places)} folders on this computer"
        body = "\n".join(p.replace(home, "~") for p in places[:5]) + ("\n…" if len(places) > 5 else "")
        self._notify(title, body + "\nDon't run or open these projects. Open RepoGuard to clean them.")

    # ---------------------------------------------------------------- derived status
    def counts(self):
        c = github.summarize(self.state["findings"])
        lc = local.summarize(self.local_findings())
        c["local_danger"], c["local_places"] = lc["danger"], lc["places"]
        c["review"] += lc["review"]
        pcf = self.pc.get("findings", [])
        c["pc_danger"] = sum(1 for f in pcf if f["severity"] == "danger")
        c["review"] += sum(1 for f in pcf if f["severity"] != "danger")
        c["total_danger"] = c["danger"] + lc["danger"] + c["pc_danger"]
        return c

    def status(self):
        """(icon, headline, detail) for the icon, menu and window."""
        c = self.counts()
        if self.checking:
            return "repoguard-busy-symbolic", "Checking…", self.progress
        if c["pc_danger"]:
            return ("repoguard-alert", f"Signs of malware on this PC ({c['pc_danger']})",
                    "Something here keeps malware running. Review it in RepoGuard.")
        if c["local_danger"]:
            n = c["local_places"]
            return ("repoguard-alert", f"Malware on this computer ({n} folder{'s' if n != 1 else ''})",
                    "Don't run or open these projects. Clean them in RepoGuard.")
        if c["danger"]:
            return ("repoguard-alert", f"Malware on {c['branches']} GitHub branch{'es' if c['branches'] != 1 else ''}",
                    f"{c['danger']} dangerous file{'s' if c['danger'] != 1 else ''}. Don't pull these branches.")
        if self.token_problem:
            return "repoguard-off-symbolic", "GitHub not connected", self.token_problem
        if self.state.get("last_error"):
            return "repoguard-off-symbolic", "Last check failed", self.state["last_error"]
        if self.settings.get("paused"):
            return "repoguard-paused-symbolic", "Watching paused", "Turn it back on from the menu."
        if not self.state.get("last_check") and not self.local.get("last_check"):
            return "repoguard-busy-symbolic", "Not checked yet", "The first check starts in a moment."
        extra = f" · {c['review']} file{'s' if c['review'] != 1 else ''} worth a look" if c["review"] else ""
        return "repoguard-ok-symbolic", "All clear", f"No malware found{extra}"

    # ---------------------------------------------------------------- UI sync
    def refresh(self):
        icon, head, detail = self.status()
        c = self.counts()
        if self.tray:
            self.tray.set_state(icon=icon, label=str(c["total_danger"]) if c["total_danger"] else "",
                                tooltip=f"{head}\n{detail}", attention=bool(c["total_danger"]))
            self.tray.set_menu(self.menu_items(head, detail, c))
        for fn in list(self.listeners):
            fn()

    def menu_items(self, head, detail, c):
        repos = len(self.state.get("repos", []))
        home = os.path.expanduser("~")
        items = [{"label": head, "enabled": False},
                 {"label": detail[:70], "enabled": False, "visible": bool(detail)},
                 {"label": f"GitHub: {repos} repos · checked {ago(self.state.get('last_check'))}", "enabled": False},
                 {"label": f"This computer: {len(self.local.get('repos', []))} repos · checked "
                           f"{ago(self.local.get('last_check'))}", "enabled": False}]
        bad_local = [k for k, f in sorted(self.local_findings().items())
                     if any(x["severity"] == "danger" for x in f["files"])]
        bad = [k for k, files in sorted(self.state["findings"].items()) if any(f["severity"] == "danger" for f in files)]
        if bad_local or bad:
            items.append({"separator": True})
            for root in bad_local[:4]:
                items.append({"label": f"⚠ {root.replace(home, '~')}", "action": self.app.show_window})
            for key in bad[:6]:
                n = sum(1 for f in self.state["findings"][key] if f["severity"] == "danger")
                items.append({"label": f"⚠ {key.replace(':', ' · ')}  ({n})", "icon": "web-browser-symbolic",
                              "action": lambda key=key: open_url(github.branch_url(key))})
            if len(bad) > 6 or len(bad_local) > 4:
                items.append({"label": "…and more", "action": self.app.show_window})
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
        # With a top-bar icon, closing the window keeps RepoGuard running there; without one, it quits.
        self.connect("close-request", self._on_close)

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

    def _on_close(self, *_):
        if self.ctl.tray and self.ctl.tray.host:
            self.set_visible(False)
            return True
        self.get_application().quit()
        return False

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
        ps = protect.status()
        g.add(Adw.ActionRow(
            title="Git protection: " + {"on": "on", "other": "off (another hooks folder is set)"}.get(ps, "off"),
            subtitle=("Fetches, pulls and clones that bring malware are cancelled before your files change."
                      if ps == "on" else "Turn it on in Settings to block infected pulls and clones.")))

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

        self._local_group()
        self._pc_group()

        local_review = [(root, x) for root, f in sorted(ctl.local_findings().items())
                        for x in f["files"] if x["severity"] != "danger"]
        pc_review = [f for f in ctl.pc.get("findings", []) if f["severity"] != "danger"]
        if review or local_review or pc_review:
            rg = self._group("Worth a look (not malware)",
                             "Normal files that can run code: GitHub workflows, .npmrc, npm install scripts, "
                             "VS Code tasks, git hooks. Check them only if you didn't add them yourself.")
            if review:
                exp = Adw.ExpanderRow(title=f"On GitHub: {len(review)} file{'s' if len(review) != 1 else ''}",
                                      subtitle=f"in {len({k for k, _ in review})} branches")
                exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
                for key, f in review:
                    exp.add_row(self._file_row(key, f, "dialog-information-symbolic", show_branch=True))
                rg.add(exp)
            if local_review:
                home = os.path.expanduser("~")
                exp = Adw.ExpanderRow(title=f"On this computer: {len(local_review)} file{'s' if len(local_review) != 1 else ''}",
                                      subtitle=f"in {len({r for r, _ in local_review})} folders")
                exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
                for root, x in local_review:
                    labels = " · ".join(dict.fromkeys(h[2] for h in x["hits"]))
                    exp.add_row(Adw.ActionRow(
                        title=GLib.markup_escape_text(x["path"]),
                        subtitle=GLib.markup_escape_text(f"{root.replace(home, '~')} · {WHERE(x['where'])} — {labels}")))
                rg.add(exp)
            if pc_review:
                exp = Adw.ExpanderRow(title=f"On this PC: {len(pc_review)} item{'s' if len(pc_review) != 1 else ''}",
                                      subtitle="Things that start by themselves or allow access. Fine if they're yours.")
                exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
                for f in pc_review:
                    exp.add_row(Adw.ActionRow(title=GLib.markup_escape_text(f["title"]),
                                              subtitle=GLib.markup_escape_text(f"{f['label']} — {f['detail'][:120]}")))
                b = Gtk.Button(label="Review…", valign=Gtk.Align.CENTER)
                b.connect("clicked", lambda *_: self.open_pc_fix())
                exp.add_suffix(b)
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

    def _local_group(self):
        ctl = self.ctl
        home = os.path.expanduser("~")
        lst = ctl.local
        folders = ", ".join(f.replace(home, "~") for f in ctl.settings.get("folders", []))
        g = self._group("Code on this computer",
                        f"Watching {folders} · {lst.get('files_checked', 0)} files in {len(lst.get('repos', []))} git "
                        f"repos · checked {ago(lst.get('last_check'))}. Files, every local branch, .git/config and "
                        "hooks are read, never run.")
        if lst.get("last_error"):
            g.add(Adw.ActionRow(title="Last check failed", subtitle=GLib.markup_escape_text(lst["last_error"])))
        bad = {k: [x for x in v["files"] if x["severity"] == "danger"] for k, v in ctl.local_findings().items()}
        bad = {k: v for k, v in bad.items() if v}
        if not bad:
            g.add(Adw.ActionRow(title="No malware found", subtitle="Every watched folder is clean."))
        for root in sorted(bad):
            files = bad[root]
            exp = Adw.ExpanderRow(title=GLib.markup_escape_text(root.replace(home, "~")),
                                  subtitle=f"{len(files)} dangerous item{'s' if len(files) != 1 else ''}")
            exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
            exp.add_css_class("error")
            cb = Gtk.Button(label="Review & clean…", valign=Gtk.Align.CENTER)
            cb.add_css_class("suggested-action")
            cb.connect("clicked", lambda *_, r=root: self.open_local_clean(r))
            exp.add_suffix(cb)
            ib = Gtk.Button(icon_name="view-conceal-symbolic", valign=Gtk.Align.CENTER,
                            tooltip_text="Ignore this folder (for example a security tool's own test files)")
            ib.add_css_class("flat")
            ib.connect("clicked", lambda *_, r=root: (ctl.ignore_folder(r), self._rebuild_local_settings(),
                                                       self.toast("Folder ignored. Undo in Settings.")))
            exp.add_suffix(ib)
            for x in sorted(files, key=lambda x: (x["where"], x["path"])):
                labels = " · ".join(dict.fromkeys(h[2] for h in x["hits"]))
                r = Adw.ActionRow(title=GLib.markup_escape_text(x["path"]),
                                  subtitle=GLib.markup_escape_text(f"{WHERE(x['where'])} — {labels}"))
                r.add_prefix(Gtk.Image.new_from_icon_name("dialog-error-symbolic"))
                exp.add_row(r)
            g.add(exp)
        ignored = ctl.local_findings(ignored=True)
        if ignored:
            g.add(Adw.ActionRow(title=f"{len(ignored)} ignored folder{'s' if len(ignored) != 1 else ''}",
                                subtitle=GLib.markup_escape_text(", ".join(r.replace(home, "~") for r in sorted(ignored))
                                                                 + " · change in Settings")))

    def _pc_group(self):
        ctl = self.ctl
        f_all = ctl.pc.get("findings", [])
        bad = [f for f in f_all if f["severity"] == "danger"]
        g = self._group("This PC", f"Crontab, services, login autostart, shell startup files, SSH keys, temp "
                                   f"folders, running programs, git/npm/VS Code settings · checked "
                                   f"{ago(ctl.pc.get('last_check'))}")
        if not bad:
            g.add(Adw.ActionRow(title="No signs of malware",
                                subtitle="Nothing here starts malware or lets someone in."))
            return
        exp = Adw.ExpanderRow(title=f"{len(bad)} sign{'s' if len(bad) != 1 else ''} of malware",
                              subtitle="Something on this PC keeps malware running or lets someone in")
        exp.add_prefix(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
        exp.add_css_class("error")
        b = Gtk.Button(label="Review & fix…", valign=Gtk.Align.CENTER)
        b.add_css_class("suggested-action")
        b.connect("clicked", lambda *_: self.open_pc_fix())
        exp.add_suffix(b)
        for f in bad:
            r = Adw.ActionRow(title=GLib.markup_escape_text(f["title"]),
                              subtitle=GLib.markup_escape_text(f"{f['label']} — {f['detail'][:140]}"))
            r.add_prefix(Gtk.Image.new_from_icon_name("dialog-error-symbolic"))
            exp.add_row(r)
        exp.set_expanded(True)
        g.add(exp)

    def open_pc_fix(self):
        from .pcdialog import PCFixDialog
        PCFixDialog(self.ctl).present(self)

    def open_local_clean(self, root):
        from .localdialog import LocalCleanDialog
        LocalCleanDialog(self.ctl, root).present(self)

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

        self._local_settings = []
        self._rebuild_local_settings()

        pg = Adw.PreferencesGroup(
            title="Git protection",
            description="Checks what git fetch, pull and clone bring in, before your files change, in the terminal, "
                        "VS Code and any other git app. Your own commits aren't checked. To let one command through "
                        "on purpose: REPOGUARD_ALLOW_FETCH=1 git …")
        self.protect_row = Adw.SwitchRow(title="Block infected pulls and clones", active=protect.status() == "on")
        self.protect_row.connect("notify::active", self._on_protect)
        pg.add(self.protect_row)
        self.settings_page.add(pg)

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

    def _rebuild_local_settings(self):
        """Folders to watch, ignored folders and past cleanings (rebuilt when they change)."""
        from . import localclean
        ctl, home = self.ctl, os.path.expanduser("~")
        for grp in self._local_settings:
            self.settings_page.remove(grp)
        self._local_settings = []

        fg = Adw.PreferencesGroup(title="Folders to watch on this computer",
                                  description="Your code folders. Every project in them is checked, including each "
                                              "git repo's local branches.")
        for f in ctl.settings.get("folders", []):
            row = Adw.ActionRow(title=GLib.markup_escape_text(f.replace(home, "~")))
            rb = Gtk.Button(icon_name="list-remove-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Stop watching")
            rb.add_css_class("flat")
            rb.connect("clicked", lambda *_, f=f: self._set_folders([x for x in ctl.settings["folders"] if x != f]))
            row.add_suffix(rb)
            fg.add(row)
        add = Adw.ButtonRow(title="Add folder…", start_icon_name="list-add-symbolic")
        add.connect("activated", lambda *_: self._pick_folder())
        fg.add(add)

        ig = Adw.PreferencesGroup(title="Ignored folders",
                                  description="Still checked, but never alert or count as malware.")
        for f in ctl.settings.get("local_ignore", []):
            row = Adw.ActionRow(title=GLib.markup_escape_text(f.replace(home, "~")))
            b = Gtk.Button(label="Stop ignoring", valign=Gtk.Align.CENTER)
            b.connect("clicked", lambda *_, f=f: (ctl.ignore_folder(f, False), self._rebuild_local_settings()))
            row.add_suffix(b)
            ig.add(row)
        if not ctl.settings.get("local_ignore"):
            ig.add(Adw.ActionRow(title="None"))

        ug = Adw.PreferencesGroup(title="Undo a cleaning",
                                  description="Every cleaning backs up the original files first.")
        past = localclean.backups()[:8]
        for qdir, undo in past:
            n = len(undo["files"]) + bool(undo.get("git_config"))
            row = Adw.ActionRow(title=GLib.markup_escape_text(undo["root"].replace(home, "~")),
                                subtitle=f"{undo['time']} · {n} file{'s' if n != 1 else ''}"
                                         + (f" · {len(undo['branches'])} branch commit(s)" if undo["branches"] else ""))
            b = Gtk.Button(label="Undo", valign=Gtk.Align.CENTER)
            b.connect("clicked", lambda *_, q=qdir: self._undo(q))
            row.add_suffix(b)
            row.add_suffix(self._delete_button(qdir, local=True))
            ug.add(row)
        if not past:
            ug.add(Adw.ActionRow(title="Nothing cleaned yet"))

        from . import fix
        hg = Adw.PreferencesGroup(title="History rewrite backups",
                                  description="Copies of GitHub repos from before a history rewrite. They still "
                                              "contain the malware (as git data; nothing in them runs). Delete each "
                                              "one once the cleaned repo is right.")
        hb = fix.list_backups()
        for path, size, mtime in hb:
            row = Adw.ActionRow(title=GLib.markup_escape_text(os.path.basename(path)[:-4].replace("__", "/")),
                                subtitle=f"{time.strftime('%d %b %H:%M', time.localtime(mtime))} · "
                                         f"{size / 1e6:.1f} MB")
            row.add_suffix(self._delete_button(path, local=False))
            hg.add(row)
        if not hb:
            hg.add(Adw.ActionRow(title="None"))

        for grp in (fg, ig, ug, hg):
            self.settings_page.add(grp)
            self._local_settings.append(grp)

    def _delete_button(self, path, local):
        from .fixdialog import confirm_delete_backup
        b = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Delete this backup")
        b.add_css_class("flat")
        b.connect("clicked", lambda *_: confirm_delete_backup(
            self, path, lambda: (self._rebuild_local_settings(), self.toast("Backup deleted.")), local=local))
        return b

    def _set_folders(self, folders):
        self.ctl.settings["folders"] = folders
        self.ctl.save_settings()
        self._rebuild_local_settings()
        self.ctl.check_now()

    def _pick_folder(self):
        dlg = Gtk.FileDialog(title="Choose a code folder to watch")

        def done(d, res):
            try:
                f = d.select_folder_finish(res)
            except GLib.Error:
                return
            path = f.get_path()
            if path and path not in self.ctl.settings["folders"]:
                self._set_folders(self.ctl.settings["folders"] + [path])
        dlg.select_folder(self, None, done)

    def _undo(self, qdir):
        from . import localclean, pcclean
        try:
            with open(os.path.join(qdir, "undo.json"), encoding="utf8") as fh:
                kind = json.load(fh).get("kind")
            res = (pcclean if kind == "pc" else localclean).restore(qdir)
            self.toast(f"Put back {res['files']} file(s)" + (f" and {len(res['branches'])} branch(es)" if res["branches"] else ""))
        except Exception as e:
            self.toast(f"Couldn't undo: {e}")
        self.ctl.check_now()

    def _on_protect(self, row, _):
        want = row.get_active()
        if want == (protect.status() == "on"):
            return
        if not want:
            ok, msg = protect.uninstall()
        else:
            ok, msg = protect.install()
            if not ok and protect.status() == "other":
                d = Adw.AlertDialog(heading="Replace git's hooks folder?",
                                    body=GLib.markup_escape_text(msg) + "\n\nRepoGuard runs each repo's own hooks, "
                                    "but hooks from that folder would stop running.")
                d.add_response("cancel", "Cancel")
                d.add_response("replace", "Replace")
                d.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
                d.set_close_response("cancel")

                def done(_d, response):
                    if response == "replace":
                        _ok, m = protect.install(force=True)
                        self.toast(m)
                    row.set_active(protect.status() == "on")
                    self.ctl.refresh()
                d.connect("response", done)
                d.present(self)
                return
        self.toast(msg)
        row.set_active(protect.status() == "on")
        self.ctl.refresh()

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
        protect.refresh()  # keep the git hooks pointing at this copy of RepoGuard
        self.ctl = Controller(self)
        self.ctl.start()

    def do_command_line(self, cmd):
        args = cmd.get_arguments()[1:]
        if "--background" not in args or not Tray.available():
            self.show_window()
        return 0

    def host_changed(self, up):
        if not up and (self.win is None or not self.win.get_visible()):
            self.show_window()  # the icon went away: show the window so RepoGuard isn't invisible

    def show_window(self):
        if self.win is None:
            self.win = Window(self, self.ctl)
        self.win.present()
        return False


def main(argv=None):
    return App().run(argv if argv is not None else sys.argv)
