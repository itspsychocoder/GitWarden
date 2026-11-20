"""This PC: places where malware hides so it keeps running or keeps access on Linux.

Checks (read-only): your crontab and the system's, systemd services and timers, login autostart entries,
shell startup files, ~/.ssh/authorized_keys, scripts and programs in /tmp, /var/tmp and /dev/shm, running
programs, global git config, ~/.npmrc, VS Code settings, and /etc/ld.so.preload.

Every finding: {"id", "kind", "where", "title", "detail", "severity", "label", "fix"}; `fix` says what
pcclean can do about it (None: tell you what to do by hand).
"""
import hashlib
import os
import re
import shutil
import subprocess

from .detect import DANGER, REVIEW, Detector

HOME = os.environ.get("GITWARDEN_PC_HOME") or os.path.expanduser("~")
ETC = os.environ.get("GITWARDEN_PC_ETC") or "/etc"
PROC = os.environ.get("GITWARDEN_PC_PROC") or "/proc"
TEMP_DIRS = (os.environ.get("GITWARDEN_PC_TMP") or "/tmp:/var/tmp:/dev/shm").split(":")
CRONTAB = os.environ.get("GITWARDEN_CRONTAB") or "crontab"

# Commands that fetch code and run it, run encoded code, or open a shell for someone else.
BAD = [
    (re.compile(r"\b(?:curl|wget|fetch)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|"
                r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:python[0-9.]*|node|perl|ruby)\b", re.I),
     "Downloads code and runs it"),
    (re.compile(r"base64\s+(?:-d|--decode)[^|\n]*\|\s*(?:ba|z|da)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", re.I),
     "Runs hidden (base64) code"),
    (re.compile(r"/dev/tcp/|\bnc\b[^\n]*\s-e\s|\bncat\b[^\n]*--exec|\bsocat\b[^\n]*exec:|bash\s+-i\s*>&", re.I),
     "Opens a shell for someone else (reverse shell)"),
    (re.compile(r"\bpython[0-9.]*\s+-c\s+['\"][^'\"]*(?:urllib|socket|requests|exec\(|eval\(|base64)", re.I),
     "Runs a hidden Python program"),
    (re.compile(r"\bnode\s+-e\s+['\"][^'\"]*(?:child_process|https?\.get|require\(['\"]https?|eval\(|Buffer\.from)", re.I),
     "Runs a hidden Node.js program"),
    (re.compile(r"jsonkeeper\.com|npoint\.io|ipcheck-si[x]|ethplorer\.io|eth_getTransaction[B]yHash", re.I),
     "Talks to a known malware server"),
    (re.compile(r"\b(?:xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|nbminer|t-rex|phoenixminer|lolminer|gminer)\b", re.I),
     "Crypto miner"),
    (None, "Runs something from a temp folder"),  # see _temp_paths: known system/app folders don't count
    (re.compile(r"LD_PRELOAD\s*=", re.I), "Forces a library into every program (LD_PRELOAD)"),
]
REMOTE_TOOLS = re.compile(r"\b(?:anydesk|teamviewer|rustdesk|screenconnect|meshagent|dwagent|hoptodesk|ngrok|"
                          r"cloudflared|frpc|chisel|tmate)\b", re.I)
TEMP_SKIP = re.compile(r"^(?:systemd-private-|snap-private-tmp|\.X\d|\.X11-unix|\.ICE-unix|\.XIM-unix|\.font-unix|"
                       r"\.Test-unix|claude-|tracker-extract|org\.chromium\.|\.org\.chromium\.|node-compile-cache|"
                       r"pulse-|ssh-[A-Za-z0-9]+$|gdm|lttng-|snap\.|mongodb-\d+\.sock|tmux-\d+|vscode-|"
                       r"\.com\.google\.Chrome|com\.google\.Chrome|rg-test-|rg-ui-|gitwarden-)")
SCRIPT_EXT = re.compile(r"\.(?:sh|bash|py|js|mjs|cjs|pl|rb|php|ps1|bat|vbs)$", re.I)
OWN_AUTOSTART = "io.github.itspsychocoder.GitWarden.desktop"


TEMP_PATH = re.compile(r"(?:^|[\s'\"=:])((?:/tmp|/var/tmp|/dev/shm)/[^\s'\";|&]+)")


def _temp_paths(text):
    """Paths in temp folders, leaving out the known system and app folders (X11, systemd, browsers…)."""
    out = [m.group(1) for m in TEMP_PATH.finditer(text or "") if _in_temp(m.group(1))]
    for t in TEMP_DIRS:  # extra temp folders (tests, or a custom TMPDIR)
        if t not in ("/tmp", "/var/tmp", "/dev/shm"):
            out += [w for w in re.split(r"[\s'\"=:;|&]+", text or "") if w.startswith(t.rstrip("/") + "/") and _in_temp(w)]
    return out


def _in_temp(path):
    """Is this file in a temp folder (and not in one of the known system/app folders there)?"""
    for t in TEMP_DIRS:
        t = t.rstrip("/") + "/"
        if path.startswith(t):
            return not TEMP_SKIP.match(path[len(t):])
    return False


def judge(text):
    """(severity, label) for a command line or script, or None. Danger for each BAD rule."""
    for rx, label in BAD:
        if rx is None:
            if _temp_paths(text):
                return DANGER, label
        elif rx.search(text or ""):
            return DANGER, label
    return None


def _id(*parts):
    return hashlib.sha1("\0".join(str(p) for p in parts).encode()).hexdigest()[:16]


def _read(path, limit=1_000_000):
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def finding(kind, where, title, detail, severity, label, fix=None):
    return {"id": _id(kind, where, detail), "kind": kind, "where": where, "title": title, "detail": detail,
            "severity": severity, "label": label, "fix": fix}


# ====================================================================== checks

def check_crontab():
    out = []
    exe = shutil.which(CRONTAB) if os.sep not in CRONTAB else CRONTAB
    if exe:
        try:
            p = subprocess.run([exe, "-l"], capture_output=True, text=True, timeout=20)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    j = judge(s)
                    if j:
                        out.append(finding("cron", "your crontab", "Scheduled command (crontab)", s, *j,
                                           fix={"type": "crontab_line", "line": line}))
        except (OSError, subprocess.TimeoutExpired):
            pass
    for path in [os.path.join(ETC, "crontab")] + _files(os.path.join(ETC, "cron.d")) + \
            [p for d in ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly") for p in _files(os.path.join(ETC, d))]:
        data = _read(path)
        if not data:
            continue
        for line in data.decode("utf8", "replace").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                j = judge(s)
                if j:
                    out.append(finding("cron", path, "System scheduled command", s, *j,
                                       fix={"type": "manual", "how": f"Needs admin: sudo nano {path}"}))
    return out


def _files(d):
    try:
        return [os.path.join(d, n) for n in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, n))]
    except OSError:
        return []


def _exec_lines(text, keys=("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "Exec")):
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.strip() in keys:
            yield v.strip()


def check_systemd():
    out = []
    user_dir = os.path.join(HOME, ".config", "systemd", "user")
    units = [(p, True) for p in _files(user_dir) if p.endswith((".service", ".timer", ".path", ".socket"))]
    units += [(p, False) for p in _files(os.path.join(ETC, "systemd", "system")) if p.endswith(".service")]
    for path, mine in units:
        data = _read(path)
        if data is None:
            continue
        text = data.decode("utf8", "replace")
        name = os.path.basename(path)
        for cmd in _exec_lines(text):
            j = judge(cmd)
            if j:
                fix = ({"type": "systemd_user", "unit": name, "path": path} if mine else
                       {"type": "manual", "how": f"Needs admin: sudo systemctl disable --now {name} && "
                                                 f"sudo rm {path}"})
                out.append(finding("systemd", path, f"Service {name}", cmd, *j, fix=fix))
                break
        else:
            if mine and not name.startswith("gitwarden"):
                out.append(finding("systemd", path, f"Your own service {name}",
                                   next(_exec_lines(text), "(no command)"), REVIEW,
                                   "Starts automatically for your user. Fine if you set it up.",
                                   fix={"type": "systemd_user", "unit": name, "path": path}))
    return out


def check_autostart():
    out = []
    for d, mine in ((os.path.join(HOME, ".config", "autostart"), True), (os.path.join(ETC, "xdg", "autostart"), False)):
        for path in _files(d):
            if not path.endswith(".desktop") or os.path.basename(path) == OWN_AUTOSTART:
                continue
            text = (_read(path) or b"").decode("utf8", "replace")
            if re.search(r"^Hidden\s*=\s*true", text, re.M | re.I):
                continue
            cmd = next(_exec_lines(text, ("Exec",)), "")
            j = judge(cmd)
            fix = {"type": "quarantine", "path": path} if mine else {"type": "manual", "how": f"Needs admin: sudo rm {path}"}
            if j:
                out.append(finding("autostart", path, f"Starts at login: {os.path.basename(path)}", cmd, *j, fix=fix))
            elif mine:
                out.append(finding("autostart", path, f"Starts at login: {os.path.basename(path)}", cmd, REVIEW,
                                   "Starts when you sign in. Fine if you added it.", fix=fix))
    return out


def check_shell_rc():
    out = []
    for name in (".bashrc", ".profile", ".bash_profile", ".bash_login", ".zshrc", ".zprofile", ".zshenv",
                 ".config/fish/config.fish", ".bash_aliases"):
        path = os.path.join(HOME, name)
        data = _read(path)
        if not data:
            continue
        for i, line in enumerate(data.decode("utf8", "replace").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            j = judge(s)
            if j:
                out.append(finding("shell", path, f"~/{name} line {i}", s, *j,
                                   fix={"type": "remove_line", "path": path, "line": line}))
    return out


def check_ssh():
    out = []
    for name in ("authorized_keys", "authorized_keys2"):
        path = os.path.join(HOME, ".ssh", name)
        data = _read(path)
        if not data:
            continue
        for line in data.decode("utf8", "replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            label = parts[-1] if len(parts) >= 3 else "(no name)"
            forced = "command=" in s.split(" ssh-")[0] if " ssh-" in s else False
            sev, why = ((DANGER, "Key with a forced command") if forced and judge(s) else
                        (REVIEW, "Lets someone log in to this computer with SSH. Remove it if you don't know it."))
            out.append(finding("ssh", path, f"SSH login key: {label}", s[:80] + ("…" if len(s) > 80 else ""),
                               sev, why, fix={"type": "remove_line", "path": path, "line": line}))
    return out


def check_temp(running):
    out = []
    det = Detector()
    for top in TEMP_DIRS:
        stack = [(top, 0)]
        while stack:
            d, depth = stack.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                if depth == 0 and TEMP_SKIP.match(e.name):
                    continue
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir():
                        if depth < 2:
                            stack.append((e.path, depth + 1))
                        continue
                    if not e.is_file() or e.stat().st_uid != os.getuid():
                        continue
                    st = e.stat()
                except OSError:
                    continue
                head = _read(e.path, 4096) or b""
                is_elf = head.startswith(b"\x7fELF")
                is_script = head.startswith(b"#!") or bool(SCRIPT_EXT.search(e.name))
                executable = bool(st.st_mode & 0o111)
                if not (is_elf or (is_script and (executable or e.path in running))):
                    continue
                body = head if is_elf else (_read(e.path, 2_000_000) or b"")
                j = None if is_elf else judge(body.decode("utf8", "replace"))
                hits = [] if is_elf else [h for h in det.check(e.name, body) if h.severity == DANGER]
                if e.path in running or j or hits:
                    sev, label = DANGER, (j[1] if j else hits[0].label if hits else "Program running from a temp folder")
                else:
                    sev, label = REVIEW, "Program or script in a temp folder"
                out.append(finding("temp", e.path, os.path.basename(e.path),
                                   ("running · " if e.path in running else "") + ("program" if is_elf else "script"),
                                   sev, label, fix={"type": "quarantine", "path": e.path}))
    return out


def processes():
    """[{pid, exe, cmd, uid}] for every process we can see."""
    out = []
    try:
        pids = [p for p in os.listdir(PROC) if p.isdigit()]
    except OSError:
        return out
    for pid in pids:
        base = os.path.join(PROC, pid)
        try:
            exe = os.readlink(os.path.join(base, "exe"))
        except OSError:
            exe = ""
        raw = _read(os.path.join(base, "cmdline"), 8000) or b""
        argv = [a.decode("utf8", "replace") for a in raw.split(b"\0") if a]
        cmd = " ".join(argv)
        try:
            uid = os.stat(base).st_uid
        except OSError:
            continue
        if cmd or exe:
            out.append({"pid": int(pid), "exe": exe, "cmd": cmd, "argv": argv, "uid": uid})
    return out


INTERP = re.compile(r"(?:node|nodejs|python[0-9.]*|bash|sh|dash|zsh|perl|ruby|php|bun|deno)$")


def _script_of(argv):
    """The script file an interpreter runs (None for `-c`/`-e` inline code or a non-interpreter)."""
    if not argv or not INTERP.match(os.path.basename(argv[0])):
        return None
    for a in argv[1:]:
        if a in ("-c", "-e", "--eval", "-p", "--print"):
            return None
        if not a.startswith("-"):
            return a
    return None


MINER_EXE = re.compile(r"^(?:xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|nbminer|t-rex|phoenixminer|lolminer|gminer)", re.I)


def _protected_pids():
    """GitWarden itself and every process that started it (your terminal, your session): never offered."""
    out, pid = {1}, os.getpid()
    for _ in range(64):
        out.add(pid)
        stat_ = _ppid(pid)
        if not stat_ or stat_ <= 1:
            break
        pid = stat_
    return out


def _ppid(pid):
    raw = _read(os.path.join(PROC, str(pid), "stat"), 4096)
    if not raw:
        return None
    try:
        return int(raw.rsplit(b")", 1)[1].split()[1])  # field after the state: parent PID
    except (IndexError, ValueError):
        return None


def check_processes(procs):
    """Danger only on hard evidence about the program itself: it runs from a temp folder, its file was
    deleted, an interpreter runs a script file from a temp folder, or it is a known miner. Suspicious text
    in a command line (a grep, an editor, a shell one-liner) is only worth a look and never stopped."""
    out = []
    skip = _protected_pids()
    for p in procs:
        if p["pid"] in skip:
            continue
        exe, cmd, argv = p["exe"], p["cmd"], p.get("argv") or p["cmd"].split()
        name = os.path.basename(exe.split(" (deleted)")[0]) or (os.path.basename(argv[0]) if argv else "")
        temp_exe = _in_temp(exe)
        deleted = exe.endswith(" (deleted)") and not exe.startswith(("/memfd:", "/usr/", "/opt/", "/snap/", "/app/"))
        script = _script_of(argv)
        temp_script = bool(script and _in_temp(script))
        miner = bool(MINER_EXE.match(name))
        if temp_exe or deleted or temp_script or miner:
            label = ("Program running from a temp folder" if temp_exe else
                     "Program whose file was deleted" if deleted else
                     "Runs a script from a temp folder" if temp_script else "Crypto miner")
            out.append(finding("process", f"pid {p['pid']}", name or cmd[:40], cmd[:200] or exe, DANGER, label,
                               fix={"type": "kill", "pid": p["pid"], "exe": exe, "cmd": cmd}))
            continue
        j = judge(cmd)
        if j and j[1] != "Runs something from a temp folder":
            out.append(finding("process", f"pid {p['pid']}", name or cmd[:40], cmd[:200], REVIEW,
                               f"Its command line looks like this: {j[1].lower()}. Fine if it's something you ran.",
                               fix={"type": "kill", "pid": p["pid"], "exe": exe, "cmd": cmd}))
        elif REMOTE_TOOLS.search(name):
            out.append(finding("process", f"pid {p['pid']}", name, cmd[:200], REVIEW,
                               "Remote-access or tunnel tool. Fine if you started it.",
                               fix={"type": "kill", "pid": p["pid"], "exe": exe, "cmd": cmd}))
    return out


def check_git_config(own_hooks):
    out = []
    path = os.path.join(HOME, ".gitconfig")
    data = _read(path)
    if not data:
        return out
    section = ""
    for line in data.decode("utf8", "replace").splitlines():
        s = line.strip()
        m = re.match(r"\[([^\]\s\"]+)(?:\s+\"([^\"]*)\")?\]", s)
        if m:
            section = m.group(1).lower() + (f".{m.group(2)}" if m.group(2) else "")
            continue
        if "=" not in s or s.startswith(("#", ";")):
            continue
        key, _, val = s.partition("=")
        key, val = f"{section}.{key.strip().lower()}", val.strip()
        if key == "core.hookspath":
            if os.path.realpath(os.path.expanduser(val)) != os.path.realpath(own_hooks):
                out.append(finding("gitconfig", path, "Git runs hooks from another folder", f"{key} = {val}",
                                   REVIEW, "Every repo runs hooks from here. Fine if you set it.",
                                   fix={"type": "git_unset", "key": key}))
            continue
        j = judge(val)
        if j or (key.startswith("alias.") and val.startswith("!") and judge(val[1:])):
            out.append(finding("gitconfig", path, f"Global git setting {key}", f"{key} = {val}", *(j or judge(val[1:])),
                               fix={"type": "git_unset", "key": key}))
    return out


def check_npmrc():
    out = []
    path = os.path.join(HOME, ".npmrc")
    data = _read(path)
    if not data:
        return out
    for line in data.decode("utf8", "replace").splitlines():
        s = line.strip()
        key = s.split("=", 1)[0].strip().lower()
        if key in ("script-shell", "node-options") or judge(s):
            out.append(finding("npm", path, f"npm setting {key}", s, DANGER,
                               "Makes every npm script run another program", fix={"type": "remove_line", "path": path, "line": line}))
        elif key == "registry" and "registry.npmjs.org" not in s:
            out.append(finding("npm", path, "npm uses another package registry", s, REVIEW,
                               "Packages come from somewhere other than npmjs.org. Fine if your company set it.",
                               fix={"type": "remove_line", "path": path, "line": line}))
    return out


def check_vscode():
    out = []
    for app in ("Code", "Code - OSS", "VSCodium", "Cursor", "Windsurf"):
        path = os.path.join(HOME, ".config", app, "User", "settings.json")
        data = _read(path)
        if not data:
            continue
        text = data.decode("utf8", "replace")
        for m in re.finditer(r'^.*"task\.allowAutomaticTasks"\s*:\s*(?:"on"|true).*$', text, re.M):
            out.append(finding("vscode", path, f"{app}: tasks run by themselves when a folder opens", m.group(0).strip(),
                               DANGER, "Lets an infected project run code as soon as you open it",
                               fix={"type": "remove_line", "path": path, "line": m.group(0)}))
    return out


def check_preload():
    path = os.path.join(ETC, "ld.so.preload")
    data = _read(path)
    if data and data.strip():
        return [finding("preload", path, "A library is forced into every program", data.decode("utf8", "replace").strip()[:200],
                        DANGER, "Common rootkit trick (/etc/ld.so.preload)",
                        fix={"type": "manual", "how": f"Needs admin. Check it, then: sudo rm {path}"})]
    return []


def scan(own_hooks="", procs=None):
    procs = processes() if procs is None else procs
    running = set()
    for p in procs:
        for tok in p["cmd"].split():
            if tok.startswith(tuple(t.rstrip("/") + "/" for t in TEMP_DIRS)):
                running.add(tok)
        if p["exe"]:
            running.add(p["exe"])
    out = []
    for fn in (check_crontab, check_systemd, check_autostart, check_shell_rc, check_ssh, check_npmrc, check_vscode,
               check_preload):
        try:
            out += fn()
        except Exception as e:  # one broken check must not hide the others
            out.append(finding("error", fn.__name__, f"Couldn't run {fn.__name__}", repr(e), REVIEW, "Check skipped"))
    out += check_temp(running) + check_processes(procs) + check_git_config(own_hooks)
    return out
