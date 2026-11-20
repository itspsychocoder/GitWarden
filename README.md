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

Connect GitHub with either:
- the GitHub CLI: `gh auth login` (RepoGuard uses `gh auth token`), or
- a fine-grained token (All repositories · Contents: Read · Metadata: Read) pasted in the app.
  It is stored in `~/.config/repoguard/github-token` (mode 600).

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

## Develop

```
python3 -m unittest discover -s tests -t . -v
```

## Roadmap

- [x] Detection engine, GitHub watch, alerts, top-bar icon, window
- [ ] Review & remove malware in local clones (preview, backup)
- [ ] Git hook that blocks pulls/fetches/clones bringing malware
- [ ] Linux PC check: crontab, systemd user units, autostart, shell rc files, ~/.ssh/authorized_keys, /tmp
- [ ] Fix on GitHub: one cleanup commit
- [ ] Rewrite history on GitHub (force-push) with mirror backup and typed confirmation
