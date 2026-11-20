"""Review & clean one folder on this computer: see every change, then clean with a backup and an Undo."""
import os
import threading

from gi.repository import Adw, GLib, Gtk

from . import localclean
from .clean import DELETE, EDIT, MANUAL
from .fixdialog import ACTION_TEXT, diff_text, diff_widget, esc, open_url


class LocalCleanDialog(Adw.Dialog):
    def __init__(self, ctl, root):
        home = os.path.expanduser("~")
        super().__init__(title=f"Clean {os.path.basename(root)}", content_width=720, content_height=680)
        self.ctl, self.root = ctl, root
        self.delete_manual = set()
        self.nav = Adw.NavigationView()
        self.set_child(self.nav)
        finding = ctl.local.get("findings", {}).get(root)
        if not finding:
            self._message("Nothing to clean", "This folder has no malware any more.")
            return
        try:
            self.pl = localclean.plan(root, finding)
        except Exception as e:
            self._message("Couldn't prepare the cleaning", f"{e!r}")
            return
        self.nav.add(self._preview(root.replace(home, "~")))

    # ------------------------------------------------------------------ pages
    def _page(self, content, title, tag):
        tv = Adw.ToolbarView(content=content)
        tv.add_top_bar(Adw.HeaderBar())
        return Adw.NavigationPage(child=tv, title=title, tag=tag)

    def _message(self, title, body):
        sp = Adw.StatusPage(icon_name="dialog-information-symbolic", title=title, description=esc(body))
        self.nav.add(self._page(sp, title, "msg"))

    def _file_row(self, f, history_note=None):
        sub = ACTION_TEXT[f["action"]]
        if f.get("notes"):
            sub += " · " + "; ".join(f["notes"][:3])
        row = Adw.ExpanderRow(title=esc(f["path"]), subtitle=esc(sub))
        row.add_prefix(Gtk.Image.new_from_icon_name(
            {EDIT: "edit-cut-symbolic", DELETE: "user-trash-symbolic", MANUAL: "dialog-warning-symbolic"}[f["action"]]))
        if f["action"] == EDIT:
            row.add_row(diff_widget(diff_text(f["old"], f["new"], f["path"])))
        elif f["action"] == DELETE:
            row.add_row(Adw.ActionRow(title="The whole file is removed (a copy goes to the backup)."))
        else:
            sw = Gtk.Switch(valign=Gtk.Align.CENTER)
            r = Adw.ActionRow(title="Delete this file", subtitle="Otherwise it stays and you clean it by hand",
                              activatable_widget=sw)
            r.add_suffix(sw)
            sw.connect("notify::active", lambda s, _, p=f["path"]:
                       (self.delete_manual.add if s.get_active() else self.delete_manual.discard)(p))
            row.add_row(r)
            row.set_expanded(True)
        return row

    def _preview(self, shown):
        pl = self.pl
        page = Adw.PreferencesPage()
        intro = Adw.PreferencesGroup(
            description=f"{esc(shown)}: everything below is backed up before it changes, and Undo puts it back.")
        page.add(intro)

        if pl["disk"]:
            g = Adw.PreferencesGroup(title="Files on disk", description="What runs when you open or start the project")
            for f in sorted(pl["disk"], key=lambda f: f["path"]):
                g.add(self._file_row(f))
            page.add(g)

        if pl.get("git_config"):
            g = Adw.PreferencesGroup(title="Git settings (.git/config)",
                                     description="These lines make git run a program. They are removed.")
            for line in pl["git_config"]["lines"]:
                r = Adw.ActionRow(title=esc(line))
                r.add_css_class("monospace")
                g.add(r)
            page.add(g)

        self.commit_current = None
        if pl["is_repo"] and pl["current"] and pl["disk"]:
            g = Adw.PreferencesGroup(title="Commit the cleanup")
            self.commit_current = Adw.SwitchRow(
                title=esc(f"Commit the cleaned files on {pl['current']}"),
                subtitle="Only these files go into the commit; anything else you changed is left as it is. "
                         "The repo's own git hooks are switched off for it.", active=True)
            g.add(self.commit_current)
            page.add(g)

        self.branch_checks = {}
        others = {b: fs for b, fs in pl["branches"].items() if b != pl.get("current")}
        if others:
            g = Adw.PreferencesGroup(title="Other local branches",
                                     description="A cleanup commit is added on top of each one you tick, without "
                                                 "checking it out.")
            for b, fs in sorted(others.items()):
                chk = Gtk.CheckButton(active=True)
                exp = Adw.ExpanderRow(title=esc(b), subtitle=f"{len(fs)} infected file{'s' if len(fs) != 1 else ''}")
                exp.add_prefix(chk)
                for f in sorted(fs, key=lambda f: f["path"]):
                    exp.add_row(self._file_row(f))
                self.branch_checks[b] = chk
                g.add(exp)
            page.add(g)

        if pl["remote"]:
            g = Adw.PreferencesGroup(
                title="Remote branches",
                description="These are copies of branches on GitHub (or another server). Clean them there: "
                            "RepoGuard's Fix… on GitHub, or tell the repo's owner.")
            for b in pl["remote"]:
                g.add(Adw.ActionRow(title=esc(b)))
            page.add(g)

        nothing = not (pl["disk"] or pl.get("git_config") or others)
        bg = Adw.PreferencesGroup()
        btn = Gtk.Button(label="Clean", halign=Gtk.Align.CENTER, sensitive=not nothing)
        btn.add_css_class("suggested-action")
        btn.add_css_class("pill")
        btn.connect("clicked", lambda *_: self._apply())
        bg.add(btn)
        if nothing:
            bg.set_description("Nothing here can be cleaned on this computer.")
        page.add(bg)
        return self._page(page, "Review & clean", "preview")

    # ------------------------------------------------------------------ apply
    def _apply(self):
        commit = bool(self.commit_current and self.commit_current.get_active())
        branches = [b for b, c in self.branch_checks.items() if c.get_active()]
        delete = set(self.delete_manual)
        sp = Adw.StatusPage(title="Cleaning…")
        sp.set_child(Adw.Spinner(width_request=48, height_request=48, halign=Gtk.Align.CENTER))
        working = self._page(sp, "Cleaning", "working")
        working.set_can_pop(False)
        self.nav.push(working)

        def work():
            try:
                res, err = localclean.apply(self.pl, delete_manual=delete, commit_current=commit, branches=branches), None
            except Exception as e:
                res, err = None, f"{e!r}"
            GLib.idle_add(self._done, res, err)
        threading.Thread(target=work, daemon=True, name="repoguard-local-clean").start()

    def _done(self, res, err):
        self.nav.pop()
        if err:
            sp = Adw.StatusPage(icon_name="dialog-error-symbolic", title="Cleaning stopped",
                                description=esc(err + "\n\nAnything already changed is in the backup; use Undo in "
                                                      "Settings to put it back."))
            self.nav.push(self._page(sp, "Error", "error"))
            return False
        page = Adw.PreferencesPage()
        sp = Adw.StatusPage(icon_name="emblem-ok-symbolic", title="Cleaned",
                            description=esc(f"{res['files']} file(s) cleaned"
                                            + (", git settings fixed" if res["git_config"] else "")
                                            + (f", cleanup commit on {', '.join(res['branches'])}" if res["branches"] else "")
                                            + "."))
        g = Adw.PreferencesGroup()
        g.add(sp)
        page.add(g)
        ng = Adw.PreferencesGroup(title="Now")
        r = Adw.ActionRow(title="Undo", subtitle="Put back everything this cleaning changed")
        ub = Gtk.Button(label="Undo", valign=Gtk.Align.CENTER)

        def undo(*_):
            out = localclean.restore(res["undo"])
            ub.set_sensitive(False)
            ub.set_label("Undone")
            r.set_subtitle(f"Put back {out['files']} file(s)" + (f" and {len(out['branches'])} branch(es)" if out["branches"] else ""))
            self.ctl.check_now()
        ub.connect("clicked", undo)
        r.add_suffix(ub)
        ng.add(r)
        br = Adw.ActionRow(title="Backup", subtitle=esc(res["undo"]))
        ob = Gtk.Button(label="Open folder", valign=Gtk.Align.CENTER)
        ob.connect("clicked", lambda *_: open_url("file://" + res["undo"]))
        br.add_suffix(ob)
        ng.add(br)
        if self.pl["remote"]:
            ng.add(Adw.ActionRow(title="Clean the remote branches too",
                                 subtitle=esc("Still infected on the server: " + ", ".join(self.pl["remote"]))))
        ng.add(Adw.ActionRow(title="Find out how it got in",
                             subtitle="Check who pushed the infected commit, and change the passwords and tokens "
                                      "used on the machine that pushed it."))
        page.add(ng)
        done = self._page(page, "Done", "done")
        done.set_can_pop(False)
        self.nav.push(done)
        self.ctl.check_now()
        return False
