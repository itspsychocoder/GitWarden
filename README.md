# RepoGuard for Linux

A top-bar app for GNOME that watches **every branch of every GitHub repo you can push to** for the git
worm that force-pushes forged commits with hidden loader code: `init` files, code hidden far off-screen
in config files, `node init &&` in npm scripts, VS Code tasks that run when a folder opens, and the
Ethereum-based loader. When new malware shows up it pops a desktop alert and the top-bar shield turns red.

Inspired by [repo-guard-windows](https://github.com/muazkhalid936/repo-guard-windows) by Muaz Khalid;
written from scratch for Linux.

RepoGuard reads files and git objects as data. It never runs anything it scans.

## Top-bar icon

| Icon | Meaning |
|---|---|
| shield ✓ | All clear |
| shield ··· | Checking |
| red shield + number | Malware found (number = dangerous files) |
| shield ‖ | Watching paused |
| shield – | GitHub not connected, or the last check failed |

Click it for a quick glance (status, last check, infected branches) and actions: **Check now**,
**Open RepoGuard…**, **Pause watching**, **Quit**.

## Install

Needs Ubuntu/Debian with GNOME (tested on Ubuntu 26.04, GNOME 50) and the system packages
`python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 git` (already there on Ubuntu desktop). Nothing from pip.

```
./install.sh            # `repoguard` command, app-menu entry, start at login
./install.sh --uninstall
```

The top-bar icon needs the **Ubuntu AppIndicators** extension (on by default on Ubuntu) or
**AppIndicator and KStatusNotifierItem Support** on other GNOME distros.

## GitHub tokens: one to watch, one to fix

This worm spreads by stealing credentials that can push, so the always-running app never holds one.

| | Watch token | Fix token |
|---|---|---|
| When | Always (background checks) | Only while you run a fix, then delete it |
| Permissions | Contents: **Read** · Metadata: Read | Contents: **Read and write** · Workflows: Read and write · Metadata: Read |
| Repos | All repositories | Only the repos you are cleaning |
| Expiry | 90 days | 7 days (delete it right after the fix) |
| Stored | `~/.config/repoguard/github-token` (mode 600) | Never written to disk: asked for at fix time, kept in memory |

Create both at GitHub → Settings → Developer settings → Fine-grained tokens. Paste the watch token in
RepoGuard → Settings.

A force-push still fails if the branch has protection or a ruleset that disallows force pushes; RepoGuard
checks this first and tells you which setting to change. Fine-grained tokens can't reach repos owned by
other people where you are only a collaborator.

## Use from the terminal

```
repoguard               # open the app
repoguard --background  # top-bar icon only
repoguard check         # one GitHub check, prints findings (exit 1 if malware)
```

## How the GitHub watch works

Each check lists your repos (ETag-cached) and their branches. A branch is only scanned when its head
commit changed. File verdicts are cached by blob SHA, so only files that actually changed are downloaded.
Large first scans are spread over several checks (max 1,500 files per check, and it stops if your API
rate limit gets low).

## Code on this computer

Every check also reads your code folders (Settings → Folders to watch; default `~/Working`): the files on
disk, every local and remote-tracking branch of each git repo, each repo's `.git/config` (settings such as
`core.fsmonitor` or `core.sshCommand` that make git run a program) and its `.git/hooks`. Files are cached by
size and time, git blobs by ID, so later checks take a fraction of a second.

**Review & clean…** shows each file it will delete or cut, with the exact code. Then it:
- backs up every file it touches to `~/.local/state/repoguard/quarantine/<time>-<folder>/` (not executable);
- cleans the files on disk and removes the dangerous `.git/config` lines;
- optionally commits the cleaned files on the checked-out branch (only those files; the repo's hooks off);
- adds a cleanup commit on other infected local branches without checking them out.

**Undo** (right after, or in Settings) puts every file and branch back. A file that changed after the preview
is left alone. Remote-tracking branches are only reported: clean them on the server (Fix… on GitHub).
**Ignore** a folder (e.g. a security tool's own test data) to stop it alerting; it is still scanned.

## This PC

Every check also looks where malware hides to keep running or keep access: your crontab and the system's,
systemd services and timers, login autostart entries, shell startup files (`~/.bashrc`, `~/.profile`,
`~/.zshrc`…), `~/.ssh/authorized_keys`, programs and scripts in `/tmp`, `/var/tmp` and `/dev/shm`, running
programs, global git config, `~/.npmrc`, VS Code's `task.allowAutomaticTasks`, and `/etc/ld.so.preload`.

- **Malware sign**: commands that download and run code, run base64-hidden code or open a reverse shell;
  programs running from a temp folder or from a deleted file; scripts run from temp folders; known miners.
- **Worth a look**: things that start by themselves or allow access (your own services and autostart
  entries, SSH keys, remote-access tools). A running program whose command line merely *mentions* something
  suspicious is only worth a look and never stopped.

**Review & fix…** ticks the malware signs (not the "worth a look" items). It stops dangerous programs (after
checking the process ID still runs the same program; never RepoGuard itself or what started it), then backs
up and removes files, lines, crontab entries and user services. Undo puts the files back; stopped programs
stay stopped. Anything that needs admin rights is listed with the command to run.

## Blocking infected pulls

Settings → **Block infected pulls and clones** (or `repoguard protect on`). RepoGuard sets git's global
`core.hooksPath` to `~/.local/share/repoguard/githooks`. Its `reference-transaction` hook reads the objects a
fetch, pull or clone just downloaded (only the new ones) and cancels the update if any file is malware, so
your branches and files never change. It works for every git app: terminal, VS Code, GitHub Desktop.

- Every other hook passes through to the repo's own `.git/hooks`, so Git LFS, pre-commit etc. keep working.
- Your own commits aren't checked.
- Let one command through on purpose (e.g. to clone an infected repo to clean it):
  `REPOGUARD_ALLOW_FETCH=1 git clone …`
- Not covered: repos that set their own `core.hooksPath` (husky), and `git fetch origin x:y` straight into a
  local branch.
- `repoguard protect off` puts git back as it was.

## Fixing malware on GitHub

Press **Fix…** on an infected branch, pick how, paste the fix token, and preview every change before anything
is pushed. You type the repository name to confirm.

- **Cleanup commit**: one normal commit on each branch you pick (no force-push). Older commits still contain the
  malware.
- **Rewrite history**: every commit on every branch (and lightweight tags) is rewritten so the malware never
  existed; commits before the infection keep their IDs, and authors, dates and messages stay the same. First a
  full `git clone --mirror` backup goes to `~/.local/state/repoguard/backups/`. The force-push is atomic and
  uses `--force-with-lease`, so if anyone pushed after your preview nothing changes. Afterwards everyone must
  re-clone, and old commits can stay reachable on GitHub by ID until GitHub Support purges them.

How each file is cleaned: files the worm adds (`init`, droppers, fake fonts) are deleted; code hidden off-screen
is cut from the line; marker lines are removed from `.gitignore`; `node init` is removed from npm scripts;
auto-run tasks are removed from `.vscode/tasks.json`. A cleaned file must pass the scanner again. Anything that
can't be cleaned safely is shown to you, and you choose whether to delete it or clean it by hand.

## Develop

```
python3 -m unittest discover -s tests -t . -v
```

## Roadmap

- [x] Detection engine, GitHub watch, alerts, top-bar icon, window
- [x] Review & remove malware in local clones (preview, backup, undo)
- [x] Git hook that blocks pulls/fetches/clones bringing malware
- [x] Linux PC check: crontab, systemd, autostart, shell rc files, SSH keys, temp folders, processes, git/npm/VS Code settings
- [x] Fix on GitHub: one cleanup commit
- [x] Rewrite history on GitHub (force-push) with mirror backup and typed confirmation
