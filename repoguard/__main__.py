"""repoguard            open the app (top-bar icon + window)
repoguard --background   start in the top bar only (used at login)
repoguard check      one GitHub check in the terminal, prints a summary (no GUI)"""
import json
import sys


def check():
    from . import config, github
    token, why = config.github_token()
    if not token:
        print(why, file=sys.stderr)
        return 2
    state = github.load_state()
    w = github.Watcher(github.GitHub(token), state, progress=lambda m: print(m, file=sys.stderr))
    res = w.run()
    github.save_state(state)
    bad = {k: v for k, v in state["findings"].items() if v}
    for key, files in sorted(bad.items()):
        print(f"\n{key}")
        for f in files:
            print(f"  {f['severity'].upper():6}  {f['path']}  ({', '.join(dict.fromkeys(h[2] for h in f['hits']))})")
    print(json.dumps({k: res[k] for k in ("repos", "branches_scanned", "incomplete", "api_calls", "rate_remaining")}))
    for e in res["errors"]:
        print("note:", e, file=sys.stderr)
    return 1 if any(f["severity"] == "danger" for v in bad.values() for f in v) else 0


def main():
    args = sys.argv[1:]
    if args[:1] == ["check"]:
        return check()
    if args[:1] in (["-h"], ["--help"]):
        print(__doc__)
        return 0
    from .app import main as app_main
    return app_main()


if __name__ == "__main__":
    sys.exit(main())
