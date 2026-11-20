"""The Fix on GitHub dialog: choose how, paste the fix token, preview every change, type the repo name, push.

The fix token only lives in this dialog (and the fix objects it creates). It is never saved, and is dropped
as soon as the fix finishes or the dialog closes.
"""
import difflib
import os
import threading

from gi.repository import Adw, Gio, GLib, Gtk

from . import fix
from .clean import DELETE, EDIT, MANUAL
from .github import GitHub, GitHubError

SUPPORT_URL = "https://support.github.com/contact"
ACTION_TEXT = {EDIT: "Cut out the malware", DELETE: "Delete file", MANUAL: "Can't clean automatically"}


def esc(s):
    return GLib.markup_escape_text(str(s))


def open_url(url):
    try:
        Gio.AppInfo.launch_default_for_uri(url, None)
    except GLib.Error:
        pass


def diff_text(old, new, path, limit=80, width=160):
    a = (old or b"").decode("utf8", "replace").splitlines()
    b = (new or b"").decode("utf8", "replace").splitlines()
    out = []
    for line in difflib.unified_diff(a, b, f"before/{path}", f"after/{path}", n=1, lineterm=""):
        if len(line) > width:
            line = line[:width] + f"   … ({len(line) - width} more characters, hidden off-screen)"
        out.append(line)
        if len(out) >= limit:
            out.append("…")
            break
    return "\n".join(out)


def diff_widget(text):
    lbl = Gtk.Label(label=text, xalign=0, yalign=0, selectable=True, wrap=False)
    lbl.add_css_class("monospace")
    lbl.set_margin_top(8)
    lbl.set_margin_bottom(8)
    lbl.set_margin_start(12)
    lbl.set_margin_end(12)
    sw = Gtk.ScrolledWindow(child=lbl, min_content_height=min(320, 18 * (text.count("\n") + 2)),
                            hscrollbar_policy=Gtk.PolicyType.AUTOMATIC, vscrollbar_policy=Gtk.PolicyType.AUTOMATIC)
    return sw


class FixDialog(Adw.Dialog):
    def __init__(self, ctl, repo, branches, preselect=None):
        super().__init__(title=f"Fix {repo}", content_width=720, content_height=680)
        self.ctl, self.repo = ctl, repo
        self.branches = sorted(branches)
        self.token = None
        self.mode = "commit"
        self.plan = None          # commit mode plan
        self.rw = None            # HistoryRewrite
        self.analysis = self.built = None
        self.delete_manual = set()
        self.busy = False
        self.connect("closed", lambda *_: self._forget())

        self.nav = Adw.NavigationView()
        self.set_child(self.nav)
        self.nav.add(self._choose_page(preselect))

    # ================================================================ page 1: choose
    def _choose_page(self, preselect):
        page = Adw.PreferencesPage()

        how = Adw.PreferencesGroup(title="How to fix")
        self.r_commit = Gtk.CheckButton(active=True)
        self.r_rewrite = Gtk.CheckButton(group=self.r_commit)
        for btn, title, sub in (
                (self.r_commit, "Cleanup commit",
                 "Adds one commit that removes the malware from the branches you pick. History isn't changed, "
                 "so older commits still contain it."),
                (self.r_rewrite, "Rewrite history (force-push)",
                 "Removes the malware from every commit on every branch and tag. A full backup is made first. "
                 "Everyone who cloned the repo must re-clone afterwards.")):
            row = Adw.ActionRow(title=title, subtitle=sub, activatable_widget=btn)
            row.add_prefix(btn)
            how.add(row)
        self.r_commit.connect("toggled", self._mode_changed)
        page.add(how)

        self.branch_group = Adw.PreferencesGroup(title="Branches", description="Infected branches in this repo")
        self.branch_checks = {}
        for b in self.branches:
            sw = Gtk.CheckButton(active=(preselect is None or b == preselect))
            row = Adw.ActionRow(title=esc(b), activatable_widget=sw)
            row.add_prefix(sw)
            self.branch_checks[b] = sw
            self.branch_group.add(row)
        page.add(self.branch_group)

        tok = Adw.PreferencesGroup(
            title="Fix token",
            description="A separate fine-grained token with write access, used only for this fix and never saved. "
                        "Delete it on GitHub when you're done.")
        self.token_row = Adw.PasswordEntryRow(title="Paste the fix token")
        self.token_row.connect("changed", lambda *_: self._update_preview_btn())
        tok.add(self.token_row)
        help_row = Adw.ActionRow(
            title="Create one",
            subtitle=f"Only select repositories → {esc(self.repo)} · Contents: Read and write · "
                     "Workflows: Read and write · Expiration: 7 days")
        b = Gtk.Button(label="Open GitHub", valign=Gtk.Align.CENTER)
        b.connect("clicked", lambda *_: open_url(fix.FIX_TOKEN_URL))
        help_row.add_suffix(b)
        tok.add(help_row)
        page.add(tok)

        self.preview_btn = Gtk.Button(label="Preview changes", halign=Gtk.Align.CENTER)
        self.preview_btn.add_css_class("suggested-action")
        self.preview_btn.add_css_class("pill")
        self.preview_btn.connect("clicked", self._start_preview)
        g = Adw.PreferencesGroup()
        g.add(self.preview_btn)
        page.add(g)
        self._update_preview_btn()

        return self._nav_page(page, "Fix on GitHub", "choose")

    def _mode_changed(self, *_):
        self.mode = "commit" if self.r_commit.get_active() else "rewrite"
        self.branch_group.set_visible(self.mode == "commit")
        self._update_preview_btn()

    def _picked(self):
        return [b for b, c in self.branch_checks.items() if c.get_active()]

    def _update_preview_btn(self):
        ok = bool(self.token_row.get_text().strip()) and (self.mode == "rewrite" or bool(self._picked()))
        self.preview_btn.set_sensitive(ok and not self.busy)

    # ================================================================ helpers
    def _nav_page(self, content, title, tag):
        tv = Adw.ToolbarView(content=content)
        tv.add_top_bar(Adw.HeaderBar())
        return Adw.NavigationPage(child=tv, title=title, tag=tag)

    def _working_page(self, title):
        self.status = Adw.StatusPage(title=title, description="Starting…")
        spin = Adw.Spinner(width_request=48, height_request=48, halign=Gtk.Align.CENTER)
        self.status.set_child(spin)
        page = self._nav_page(self.status, title, "working")
        page.set_can_pop(False)
        return page

    def _progress(self, msg):
        GLib.idle_add(lambda: (self.status.set_description(esc(msg)), False)[1])

    def _run(self, title, work, done):
        """Run work() in a thread behind a spinner page; then done(result) or the error page."""
        self.busy = True
        self.nav.push(self._working_page(title))

        def thread():
            try:
                res, err = work(), None
            except GitHubError as e:
                res, err = None, fix.friendly(e)
            except fix.GitError as e:
                res, err = None, fix.friendly(e)
            except Exception as e:
                res, err = None, f"Unexpected error: {e!r}"
            GLib.idle_add(finish, res, err)

        def finish(res, err):
            self.busy = False
            self.nav.pop()
            if err:
                self._error(err)
            else:
                done(res)
            return False

        threading.Thread(target=thread, daemon=True, name="repoguard-fix").start()

    def _error(self, msg):
        sp = Adw.StatusPage(icon_name="dialog-error-symbolic", title="Nothing was changed on GitHub",
                            description=esc(msg))
        b = Gtk.Button(label="Back", halign=Gtk.Align.CENTER)
        b.add_css_class("pill")
        b.connect("clicked", lambda *_: self.nav.pop())
        sp.set_child(b)
        self.nav.push(self._nav_page(sp, "Couldn't fix", "error"))

    def _forget(self):
        """Drop the fix token everywhere it is held."""
        self.token = None
        try:
            self.token_row.set_text("")
        except Exception:
            pass
        if self.rw:
            self.rw.close()
            self.rw = None

    # ================================================================ preview
    def _start_preview(self, *_):
        self.token = self.token_row.get_text().strip()
        self.delete_manual = set()
        if self.rw:
            self.rw.close()
            self.rw = None
        if self.mode == "commit":
            branches = self._picked()
            verdicts = self.ctl.state.get("blob_verdicts", {})

            def work():
                gh = GitHub(self.token)
                return fix.CommitFix(gh, self.repo, verdicts=verdicts, progress=self._progress).plan(branches)
            self._run("Preparing the cleanup", work, self._show_commit_preview)
        else:
            token = self.token

            def work():
                rw = fix.HistoryRewrite(self.repo, token, progress=self._progress)
                try:
                    rw.prepare()
                    analysis = rw.analyze()
                    built = rw.build()
                    gh = GitHub(token)
                    prot = {b["branch"]: fix.protection(gh, self.repo, b["branch"]) for b in built["branches"]}
                except Exception:
                    rw.close()
                    raise
                return rw, analysis, built, prot
            self._run("Preparing the history rewrite", work, self._show_rewrite_preview)

    def _file_rows(self, group, files, history=False):
        for f in files:
            sub = ACTION_TEXT[f["action"]]
            if f.get("notes"):
                sub += " · " + "; ".join(f["notes"][:3])
            if history:
                sub += f" · {f['versions']} version{'s' if f['versions'] != 1 else ''} in history"
            row = Adw.ExpanderRow(title=esc(f["path"]), subtitle=esc(sub))
            row.add_prefix(Gtk.Image.new_from_icon_name(
                {EDIT: "edit-cut-symbolic", DELETE: "user-trash-symbolic", MANUAL: "dialog-warning-symbolic"}[f["action"]]))
            old, new = (f.get("example") or (None, None)) if history else (f.get("old"), f.get("new"))
            if f["action"] == EDIT and (old or new):
                row.add_row(diff_widget(diff_text(old, new, f["path"])))
            elif f["action"] == DELETE:
                row.add_row(Adw.ActionRow(title="The whole file is removed."))
            if f["action"] == MANUAL:
                sw = Gtk.Switch(valign=Gtk.Align.CENTER)
                r = Adw.ActionRow(title="Delete this file" + (" everywhere in history" if history else ""),
                                  subtitle="Otherwise it stays and you clean it by hand", activatable_widget=sw)
                r.add_suffix(sw)
                sw.connect("notify::active", lambda s, _, p=f["path"], fobj=f: self._toggle_manual(p, s.get_active(), fobj))
                row.add_row(r)
                row.set_expanded(True)
            group.add(row)

    def _toggle_manual(self, path, on, f):
        (self.delete_manual.add if on else self.delete_manual.discard)(path)
        if self.mode == "commit":
            f["action"] = DELETE if on else MANUAL

    def _show_commit_preview(self, plan):
        self.plan = plan
        page = Adw.PreferencesPage()
        total = 0
        for br in plan["branches"]:
            g = Adw.PreferencesGroup(title=esc(br["branch"]),
                                     description=f"One new commit on top of {br['head'][:7]}")
            if not br["files"]:
                g.add(Adw.ActionRow(title="Already clean", subtitle="Nothing to change on this branch."))
            self._file_rows(g, br["files"])
            total += len(br["files"])
            page.add(g)
        self._confirm_group(page, "Push cleanup commit", can=total > 0)
        self.nav.push(self._nav_page(page, "Preview", "preview"))

    def _show_rewrite_preview(self, res):
        self.rw, self.analysis, self.built, prot = res
        a, b = self.analysis, self.built
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title="What changes")
        g.add(Adw.ActionRow(title=f"{a['commits_affected']} of {a['commits_total']} commits contain malware",
                            subtitle=f"{b['commits_rewritten']} commits get new IDs (those after the infection). "
                                     "Authors, dates and messages stay the same."))
        if not b["branches"] and not b["tags"]:
            g.add(Adw.ActionRow(title="History is already clean", subtitle="Nothing to force-push."))
        for br in b["branches"]:
            p = prot.get(br["branch"], {})
            row = Adw.ActionRow(title=esc(f"Force-push {br['branch']}"),
                                subtitle=f"{br['old'][:7]} → {br['new'][:7]}")
            if p.get("force_push") == "blocked":
                row.set_subtitle(esc(f"{br['old'][:7]} → {br['new'][:7]} · BLOCKED: {p['detail']}. Allow force "
                                     "pushes for this branch on GitHub first, then preview again."))
                row.add_prefix(Gtk.Image.new_from_icon_name("dialog-error-symbolic"))
            elif p.get("force_push") == "unknown":
                row.set_subtitle(esc(f"{br['old'][:7]} → {br['new'][:7]} · {p['detail']}: the push may be refused"))
            g.add(row)
        for t in b["tags"]:
            g.add(Adw.ActionRow(title=esc(f"Move tag {t['tag']}"), subtitle=f"{t['old'][:7]} → {t['new'][:7]}"))
        for t in b["annotated_tags_left"]:
            g.add(Adw.ActionRow(title=esc(f"Annotated tag {t} still points at an infected commit"),
                                subtitle="Delete it and tag again after the fix."))
        g.add(Adw.ActionRow(title="Backup of the original repo", subtitle=esc(a["backup"])))
        page.add(g)

        fg = Adw.PreferencesGroup(title="Files", description="Every infected file found anywhere in branch history")
        self._file_rows(fg, a["files"], history=True)
        page.add(fg)
        blocked = any(p.get("force_push") == "blocked" for p in prot.values())
        self._confirm_group(page, "Force-push cleaned history", can=bool(b["branches"] or b["tags"]) and not blocked,
                            destructive=True)
        self.nav.push(self._nav_page(page, "Preview", "preview"))

    def _confirm_group(self, page, label, can, destructive=False):
        g = Adw.PreferencesGroup(title="Confirm", description=f"Type {esc(self.repo)} to confirm.")
        entry = Adw.EntryRow(title="Repository name")
        btn = Gtk.Button(label=label, halign=Gtk.Align.CENTER, sensitive=False)
        btn.add_css_class("destructive-action" if destructive else "suggested-action")
        btn.add_css_class("pill")
        entry.connect("changed", lambda e: btn.set_sensitive(can and e.get_text().strip() == self.repo))
        btn.connect("clicked", lambda *_: self._apply())
        g.add(entry)
        page.add(g)
        bg = Adw.PreferencesGroup()
        bg.add(btn)
        page.add(bg)

    # ================================================================ apply
    def _apply(self):
        if self.mode == "commit":
            plan, token = self.plan, self.token

            def work():
                return fix.CommitFix(GitHub(token), self.repo, progress=self._progress).apply(plan)
            self._run("Pushing the cleanup commit", work, self._done)
        else:
            rw, delete = self.rw, set(self.delete_manual)

            def work():
                if delete:
                    rw.build(delete_paths=delete)
                return rw.push()
            self._run("Force-pushing the cleaned history", work, self._done)

    def _done(self, _res):
        backup = self.analysis["backup"] if self.analysis else None
        self._forget()
        page = Adw.PreferencesPage()
        sp = Adw.StatusPage(icon_name="emblem-ok-symbolic", title="Malware removed on GitHub",
                            description="RepoGuard will check the repo again now.")
        sg = Adw.PreferencesGroup()
        sg.add(sp)
        page.add(sg)

        g = Adw.PreferencesGroup(title="Now do this")
        row = Adw.ActionRow(title="Delete the fix token", subtitle="RepoGuard has already forgotten it.")
        b = Gtk.Button(label="Open GitHub tokens", valign=Gtk.Align.CENTER)
        b.add_css_class("suggested-action")
        b.connect("clicked", lambda *_: open_url(fix.TOKEN_LIST_URL))
        row.add_suffix(b)
        g.add(row)
        if self.mode == "rewrite":
            g.add(Adw.ActionRow(
                title="Tell everyone who cloned it to re-clone",
                subtitle=esc("Or: git fetch && git reset --hard origin/<branch>. If they push their old copy, "
                             "the malware comes back.")))
            r = Adw.ActionRow(
                title="Ask GitHub to purge the old commits",
                subtitle="Old commits can stay reachable by their ID (forks, pull requests, cached views) until "
                         "GitHub Support removes them.")
            sb = Gtk.Button(label="GitHub Support", valign=Gtk.Align.CENTER)
            sb.connect("clicked", lambda *_: open_url(SUPPORT_URL))
            r.add_suffix(sb)
            g.add(r)
            if backup:
                r = Adw.ActionRow(title="Backup of the original repo", subtitle=esc(backup))
                ob = Gtk.Button(label="Open folder", valign=Gtk.Align.CENTER)
                ob.connect("clicked", lambda *_: open_url("file://" + os.path.dirname(backup)))
                r.add_suffix(ob)
                g.add(r)
        page.add(g)
        done = self._nav_page(page, "Done", "done")
        done.set_can_pop(False)
        self.nav.push(done)
        self.ctl.check_now()
