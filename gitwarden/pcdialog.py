"""Review & fix what the PC check found. Dangerous items are ticked; "worth a look" items are not."""
import threading

from gi.repository import Adw, GLib, Gtk

from . import pcclean
from .fixdialog import esc, open_url

KIND = {"cron": "Scheduled commands", "systemd": "Services", "autostart": "Starts at login",
        "shell": "Shell startup files", "ssh": "SSH login keys", "temp": "Temp folders", "process": "Running programs",
        "gitconfig": "Git settings", "npm": "npm settings", "vscode": "VS Code settings", "preload": "System libraries",
        "error": "Checks that couldn't run"}
ACTION = {"kill": "Stop the program", "quarantine": "Move the file to the backup", "remove_line": "Remove this line",
          "crontab_line": "Remove this scheduled command", "systemd_user": "Stop, disable and remove the service",
          "git_unset": "Remove this git setting"}


class PCFixDialog(Adw.Dialog):
    def __init__(self, ctl):
        super().__init__(title="This PC", content_width=720, content_height=680)
        self.ctl = ctl
        self.checks = []
        self.nav = Adw.NavigationView()
        self.set_child(self.nav)
        self.nav.add(self._preview())

    def _page(self, content, title, tag):
        tv = Adw.ToolbarView(content=content)
        tv.add_top_bar(Adw.HeaderBar())
        return Adw.NavigationPage(child=tv, title=title, tag=tag)

    def _preview(self):
        findings = sorted(self.ctl.pc.get("findings", []), key=lambda f: (f["severity"] != "danger", f["kind"]))
        page = Adw.PreferencesPage()
        page.add(Adw.PreferencesGroup(description="Tick what to fix. Files are backed up first and Undo puts them "
                                                  "back; a stopped program stays stopped."))
        groups = {}
        for f in findings:
            g = groups.get(f["kind"])
            if g is None:
                g = groups[f["kind"]] = Adw.PreferencesGroup(title=KIND.get(f["kind"], f["kind"]))
                page.add(g)
            fx = f.get("fix") or {}
            row = Adw.ExpanderRow(title=esc(f["title"]), subtitle=esc(f["label"]))
            if fx.get("type") in ACTION:
                chk = Gtk.CheckButton(active=f["severity"] == "danger", valign=Gtk.Align.CENTER)
                row.add_prefix(chk)
                self.checks.append((chk, f))
            else:
                row.add_prefix(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
            detail = Gtk.Label(label=f["detail"], xalign=0, wrap=True, selectable=True, margin_top=8, margin_bottom=8,
                               margin_start=12, margin_end=12)
            detail.add_css_class("monospace")
            row.add_row(detail)
            where = Adw.ActionRow(title="Where", subtitle=esc(f["where"]))
            row.add_row(where)
            how = ACTION.get(fx.get("type")) or fx.get("how") or "Nothing GitWarden can do automatically"
            row.add_row(Adw.ActionRow(title="Fix", subtitle=esc(how)))
            if f["severity"] == "danger":
                row.add_css_class("error")
            g.add(row)
        if not findings:
            page.add(Adw.PreferencesGroup(description="Nothing found."))
        bg = Adw.PreferencesGroup()
        btn = Gtk.Button(label="Fix ticked items", halign=Gtk.Align.CENTER, sensitive=bool(self.checks))
        btn.add_css_class("suggested-action")
        btn.add_css_class("pill")
        btn.connect("clicked", lambda *_: self._apply())
        bg.add(btn)
        page.add(bg)
        return self._page(page, "Review & fix", "preview")

    def _apply(self):
        picked = [f for chk, f in self.checks if chk.get_active()]
        if not picked:
            return
        sp = Adw.StatusPage(title="Fixing…")
        sp.set_child(Adw.Spinner(width_request=48, height_request=48, halign=Gtk.Align.CENTER))
        working = self._page(sp, "Fixing", "working")
        working.set_can_pop(False)
        self.nav.push(working)

        def work():
            try:
                res, err = pcclean.apply(picked), None
            except Exception as e:
                res, err = None, repr(e)
            GLib.idle_add(self._done, res, err)
        threading.Thread(target=work, daemon=True, name="gitwarden-pc-fix").start()

    def _done(self, res, err):
        self.nav.pop()
        page = Adw.PreferencesPage()
        if err:
            page.add(Adw.PreferencesGroup(title="Fixing stopped", description=esc(
                err + "\n\nAnything already changed is in the backup; Undo is in Settings.")))
        else:
            g = Adw.PreferencesGroup(title="Done")
            for d in res["done"]:
                g.add(Adw.ActionRow(title=esc(d)))
            if not res["done"]:
                g.add(Adw.ActionRow(title="Nothing changed"))
            page.add(g)
            if res["skipped"]:
                sg = Adw.PreferencesGroup(title="Left for you", description="Do these by hand")
                for title, why in res["skipped"]:
                    r = Adw.ActionRow(title=esc(title), subtitle=esc(why))
                    r.set_subtitle_selectable(True)
                    sg.add(r)
                page.add(sg)
            ng = Adw.PreferencesGroup(title="Now")
            r = Adw.ActionRow(title="Undo", subtitle="Put back the files, crontab and services this changed")
            ub = Gtk.Button(label="Undo", valign=Gtk.Align.CENTER)

            def undo(*_):
                out = pcclean.restore(res["undo"])
                ub.set_sensitive(False)
                ub.set_label("Undone")
                r.set_subtitle(f"Put back {out['files']} item(s)")
                self.ctl.check_now()
            ub.connect("clicked", undo)
            r.add_suffix(ub)
            ng.add(r)
            br = Adw.ActionRow(title="Backup", subtitle=esc(res["undo"]))
            ob = Gtk.Button(label="Open folder", valign=Gtk.Align.CENTER)
            ob.connect("clicked", lambda *_: open_url("file://" + res["undo"]))
            br.add_suffix(ob)
            ng.add(br)
            ng.add(Adw.ActionRow(title="Change your passwords and tokens",
                                 subtitle="If malware ran here, assume it saw your GitHub, npm and SSH credentials: "
                                          "revoke and recreate them from a clean machine."))
            page.add(ng)
        done = self._page(page, "Done", "done")
        done.set_can_pop(False)
        self.nav.push(done)
        self.ctl.check_now()
        return False
