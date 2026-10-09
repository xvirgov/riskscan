#!/usr/bin/env python3
"""Git-layer adapter for riskscan — the authoritative secret scan.

The Claude Code adapter sees a *command string* and has to predict what a shell will do to
the filesystem. A git hook does not: git runs it inside the repository with the index already
built, so "which tree, which files, which content" are facts rather than guesses. That is why
this layer blocks and the agent layer only warns.

Modes:
  --staged              scan the staged blobs      (pre-commit)
  --pre-push            scan the pushed range from git's stdin   (pre-push)
  --install [--global]  write the hooks; --global also sets core.hooksPath
  --uninstall [--global]
  --status              report whether the hooks are installed
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from riskscan import engine  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, os.path.basename(__file__))
MARKER = engine.HOOK_MARKER            # "# >>> riskscan >>>"
END_MARKER = "# <<< riskscan <<<"
GLOBAL_DIR = os.path.expanduser("~/.githooks")
ZERO = "0" * 40


def _git(args, cwd=None):
    try:
        p = subprocess.run(["git"] + args, capture_output=True, text=True, cwd=cwd, timeout=30)
    except Exception:
        return None
    return p.stdout if p.returncode == 0 else None


def _block_threshold():
    cfg = (engine.CONFIG.get("secrets") or {})
    return int(cfg.get("block_threshold", 9))


def _git_bytes(args):
    """Raw bytes from git — `_git` decodes as text, which corrupts a binary blob."""
    try:
        p = subprocess.run(["git"] + args, capture_output=True, timeout=30)
    except Exception:
        return None
    return p.stdout if p.returncode == 0 else None


def _hook_skips():
    """Paths this layer declines to scan — empty by default, i.e. everything staged is scanned.

    `secrets.skip_paths` exists to keep a *changeset preview* quiet in the agent layer, where
    fixture trees are mostly noise. It is the wrong policy for the gate: `tests/fixtures/` is
    exactly where a credential gets parked "temporarily" and then committed. Opt back in with
    `secrets.hook_skip_paths` if a repo makes that unworkable.
    """
    return (engine.CONFIG.get("secrets") or {}).get("hook_skip_paths", [])


def _skipper():
    skips = _hook_skips()
    return (lambda path: engine._secret_skip(path, skips)) if skips else None


# ── gathering what is actually being committed / pushed ──────────────────────
def staged_items():
    """(all staged paths, readable (relpath, content) pairs, unreadable paths).

    The three are separate on purpose. "Nothing staged" and "nothing the builtin can read" are
    different states, and conflating them used to skip gitleaks entirely whenever the builtin's
    list came back empty.

    Read with `git show :<path>`, i.e. the blob in the index — NOT the working-tree file. After
    `git add -p` those differ, and it is the staged version that becomes the commit.
    """
    out = _git(["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"])
    names = [r for r in (out or "").split("\0") if r.strip()]
    skips = _hook_skips()
    items, unreadable = [], []
    for rel in names:
        if skips and engine._secret_skip(rel, skips):
            continue
        blob = _git(["show", ":" + rel])
        if blob is None or "\0" in blob[:8000]:
            unreadable.append(rel)      # binary: gitleaks still scans it, the builtin cannot
            continue
        items.append((rel, blob))
    return names, items, unreadable


_DIFF_FILE = re.compile(r"^\+\+\+ b/(.*)$")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")


def range_items(rev_args):
    """(relpath, added lines) per file across a commit range, from `git log -p`.

    `rev_args` is a LIST of revision arguments, never one string: `["<sha>", "--not",
    "--remotes"]` passed as a single token reaches git as a literal filename and the scan
    silently finds nothing — which is exactly how a new branch slipped through unscanned.

    Added lines are what a push introduces, and reading them from the patch catches a secret
    that was committed and later removed — still in the history being pushed, invisible to any
    working-tree scan.
    """
    out = _git(["log", "-p", "--no-merges", "--no-color", "--unified=0"] + list(rev_args))
    if not out:
        return []
    per, cur, line_no = {}, None, 0
    for ln in out.splitlines():
        m = _DIFF_FILE.match(ln)
        if m:
            cur, line_no = m.group(1), 0
            continue
        h = _HUNK.match(ln)
        if h:
            line_no = int(h.group(1))
            continue
        if cur and ln.startswith("+") and not ln.startswith("+++"):
            per.setdefault(cur, []).append((line_no, ln[1:]))
            line_no += 1
    items = []
    skips = _hook_skips()
    for rel, rows in per.items():
        if skips and engine._secret_skip(rel, skips):
            continue
        # pad to the real line numbers so a reported location matches the file
        text, at = [], 1
        for n, content in rows:
            while at < n:
                text.append("")
                at += 1
            text.append(content)
            at += 1
        items.append((rel, "\n".join(text)))
    return items


# ── scanning ─────────────────────────────────────────────────────────────────
def scan(items, label, gitleaks_argv=None, unreadable=()):
    """Run the same analyzers the agent layer uses, and return an engine-shaped report."""
    findings, skipped = [], []
    ignores = engine.load_ignores(os.getcwd())   # git runs hooks from the worktree root
    supp, fps = [], {}
    for rel, text in items:
        sc, fs = engine._secret_scan(text, rel, ignores, supp, fps)
        for s, lbl in fs:
            findings.append(("builtin:secrets", s, "%s (%s)" % (lbl, label)))

    gl = shutil.which("gitleaks")
    if gl and gitleaks_argv is not None:
        try:
            proc = subprocess.run([gl] + gitleaks_argv, capture_output=True, text=True, timeout=120)
            if proc.returncode in (0, 1):
                parsed = engine.parse_gitleaks(proc.stdout, skip=_skipper(),
                                               ignores=ignores, suppressed=supp, fps=fps)
                if parsed:
                    for s, lbl in parsed[1]:
                        if not lbl.startswith("no findings"):
                            findings.append(("gitleaks", s, lbl))
            else:
                skipped.append(("gitleaks", "secrets", "exited %d" % proc.returncode, ""))
        except Exception as e:
            skipped.append(("gitleaks", "secrets", "error: %s" % e, ""))
    elif not gl:
        skipped.append(("gitleaks", "secrets", "not installed", "brew install gitleaks"))
    if unreadable:
        # `git diff` emits only "Binary files ... differ", so a staged keystore is invisible to
        # BOTH analyzers: the builtin cannot decode it and gitleaks (diff mode) gets no content.
        # `gitleaks dir` over the extracted blobs does see it — that is the only way in.
        found, why = _scan_binaries(unreadable, gl, ignores, supp, fps)
        findings += found
        if why:
            skipped.append(("gitleaks", "secrets", "%d binary file(s) not scanned (%s): %s"
                            % (len(unreadable), why, ", ".join(unreadable[:3])), ""))

    skipped += [("builtin:secrets", "secrets", n, "")
                for n in engine._suppression_notes(supp)]
    scores = [s for _, s, _ in findings]
    overall = max(scores) if scores else 0
    state = engine.state_of(overall) if findings else engine.NOT_ANALYZED
    return {"surfaces": ["secrets"], "findings": findings, "skipped": skipped,
            "overall": overall, "state": state, "fingerprints": fps}


def _scan_binaries(paths, gl, ignores=None, supp=None, fps=None):
    """(findings, reason-it-could-not-run) for staged binary blobs, via `gitleaks dir`.

    The blobs are written under their real basenames: gitleaks has filename-driven rules
    (pkcs12-file, and the like) that would not fire against a generated temp name.
    """
    if not gl:
        return [], "gitleaks not installed"
    tmpdir = tempfile.mkdtemp()
    try:
        wrote = 0
        for rel in paths[:20]:
            blob = _git_bytes(["show", ":" + rel])
            if blob is None:
                continue
            dest = os.path.normpath(os.path.join(tmpdir, rel))
            if not dest.startswith(tmpdir + os.sep):
                continue
            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            with open(dest, "wb") as f:
                f.write(blob)
            wrote += 1
        if not wrote:
            return [], "could not extract the blobs"
        proc = subprocess.run([gl, "dir", tmpdir, "-f", "json", "-r", "-",
                               "--no-banner", "--redact"],
                              capture_output=True, text=True, timeout=120)
        if proc.returncode not in (0, 1):
            return [], "gitleaks exited %d" % proc.returncode
        parsed = engine.parse_gitleaks(proc.stdout.replace(tmpdir + os.sep, ""),
                                       skip=_skipper(), ignores=ignores, suppressed=supp, fps=fps)
        if not parsed:
            return [], "unparseable output"
        return [("gitleaks", sc, lbl) for sc, lbl in parsed[1]
                if not lbl.startswith("no findings")], None
    except Exception as e:
        return [], "error: %s" % e
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def report_and_exit(report, what):
    if not report["findings"] and not report["skipped"]:
        return 0
    if report["findings"]:
        sys.stderr.write(engine.render_banner(report) + "\n")
    for name, _, reason, hint in report["skipped"]:
        sys.stderr.write("  ⚪ [%s] not analyzed — %s%s\n"
                         % (name, reason, " → " + hint if hint else ""))
    if report["overall"] >= _block_threshold():
        sys.stderr.write(
            "\nriskscan: blocked — a credential of unambiguous shape is in what you are about to "
            "%s.\n  Remove it, or bypass once with --no-verify / RISKSCAN_SKIP=1.\n" % what)
        # Paste-ready, because making someone assemble a fingerprint by hand is how an allowlist
        # ends up unused and the bypass becomes the habit.
        fps = report.get("fingerprints") or {}
        blocking = []
        for _, sc, lbl in report["findings"]:
            if sc < _block_threshold():
                continue
            # the builtin's labels gain a " (staged)" / " (push)" suffix on the way into a report
            fp = fps.get(lbl) or fps.get(lbl.rsplit(" (", 1)[0])
            if fp:
                blocking.append(fp)
        if blocking:
            sys.stderr.write("\n  If a finding is a false positive, add it to .riskscanignore:\n")
            for fp in dict.fromkeys(blocking):
                sys.stderr.write("    %s   # why\n" % fp)
        return 1
    return 0


def run_staged():
    names, items, unreadable = staged_items()
    if not names:
        return 0  # nothing staged; a commit here is a no-op or a merge
    return report_and_exit(scan(items, "staged",
                                ["git", "--staged", "-f", "json", "-r", "-",
                                 "--no-banner", "--redact"], unreadable), "commit")


def run_pre_push():
    """git feeds `<local ref> <local sha> <remote ref> <remote sha>` lines on stdin."""
    rc = 0
    try:
        lines = sys.stdin.read().splitlines()
    except Exception:
        return 0
    for ln in lines:
        parts = ln.split()
        if len(parts) < 4:
            continue
        local_sha, remote_sha = parts[1], parts[3]
        if local_sha == ZERO:
            continue  # branch deletion — nothing to scan
        if remote_sha == ZERO:  # new branch: everything on it that no remote has yet
            rev_args, log_opts = [local_sha, "--not", "--remotes"], "%s --not --remotes" % local_sha
        else:
            rev_args = ["%s..%s" % (remote_sha, local_sha)]
            log_opts = rev_args[0]
        items = range_items(rev_args)
        if not items:
            continue
        r = scan(items, "push", ["git", ".", "--log-opts", log_opts, "-f", "json", "-r", "-",
                                 "--no-banner", "--redact"])
        rc = max(rc, report_and_exit(r, "push"))
    return rc


# ── installer ────────────────────────────────────────────────────────────────
def _script(kind):
    """A hook body that chains whatever hook it replaces, then runs riskscan.

    The chain matters: `core.hooksPath` *overrides* `.git/hooks`, so a global install would
    otherwise silently disable the pre-commit framework in every repo that uses it. The local
    path is taken from `--absolute-git-dir`, never `--git-path hooks`, which would resolve back
    to core.hooksPath and make the hook exec itself.
    """
    py = sys.executable if os.path.basename(sys.executable).startswith("python") else "python3"
    forward = '''
_local="$(git rev-parse --absolute-git-dir 2>/dev/null)/hooks/%(kind)s"
if [ -x "$_local" ] && ! grep -q '>>> riskscan >>>' "$_local" 2>/dev/null; then
''' % {"kind": kind}
    if kind == "pre-push":
        body = forward + '''  printf '%%s\\n' "$_stdin" | "$_local" "$@" || exit $?
fi
printf '%%s\\n' "$_stdin" | exec "%(py)s" "%(adapter)s" --pre-push
''' % {"py": py, "adapter": ADAPTER}
        pre = '_stdin="$(cat)"\n'
    else:
        body = forward + '''  "$_local" "$@" || exit $?
fi
exec "%(py)s" "%(adapter)s" --staged
''' % {"py": py, "adapter": ADAPTER}
        pre = ""
    return ('#!/bin/sh\n%s\n# installed by `riskscan --install-git-hooks`; remove with --uninstall\n'
            '[ -n "$RISKSCAN_SKIP" ] && exit 0\n%s%s%s\n' % (MARKER, pre, body, END_MARKER))


def install(global_scope):
    target = GLOBAL_DIR if global_scope else None
    if not global_scope:
        gd = _git(["rev-parse", "--absolute-git-dir"])
        if not gd:
            print("riskscan: not inside a git repository (use --global for every repo)")
            return 1
        target = os.path.join(gd.strip(), "hooks")
    if global_scope:
        cur = _git(["config", "--global", "--get", "core.hooksPath"])
        cur = (cur or "").strip()
        if cur and os.path.expanduser(cur) != GLOBAL_DIR:
            print("riskscan: core.hooksPath is already set to %s — refusing to overwrite it.\n"
                  "  Install into that directory yourself, or unset it first." % cur)
            return 1
    if not os.path.isdir(target):
        os.makedirs(target)
    for kind in ("pre-commit", "pre-push"):
        path = os.path.join(target, kind)
        if os.path.exists(path):
            with open(path) as f:
                existing = f.read()
            if MARKER not in existing:
                backup = path + ".pre-riskscan"
                shutil.copy2(path, backup)
                print("  kept your existing %s as %s (it is chained, not replaced)"
                      % (kind, os.path.basename(backup)))
        with open(path, "w") as f:
            f.write(_script(kind))
        os.chmod(path, 0o755)
        print("  wrote %s" % path)
    if global_scope:
        subprocess.run(["git", "config", "--global", "core.hooksPath", GLOBAL_DIR], check=False)
        print("  set core.hooksPath = %s (every repo, including ones you clone later)" % GLOBAL_DIR)
    print("riskscan: git hooks installed. Blocking threshold: %d/10." % _block_threshold())
    return 0


def uninstall(global_scope):
    target = GLOBAL_DIR
    if not global_scope:
        gd = _git(["rev-parse", "--absolute-git-dir"])
        if not gd:
            print("riskscan: not inside a git repository")
            return 1
        target = os.path.join(gd.strip(), "hooks")
    for kind in ("pre-commit", "pre-push"):
        path = os.path.join(target, kind)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            if MARKER not in f.read():
                print("  %s is not ours — left alone" % path)
                continue
        os.remove(path)
        backup = path + ".pre-riskscan"
        if os.path.exists(backup):
            shutil.move(backup, path)
            print("  removed ours and restored %s" % path)
        else:
            print("  removed %s" % path)
    if global_scope:
        subprocess.run(["git", "config", "--global", "--unset", "core.hooksPath"], check=False)
        print("  unset core.hooksPath")
    return 0


def status():
    installed = engine.git_hooks_installed(os.getcwd())
    hp = (_git(["config", "--get", "core.hooksPath"]) or "").strip() or "(unset)"
    print("riskscan git hooks : %s" % ("installed" if installed else "NOT installed"))
    print("core.hooksPath     : %s" % hp)
    print("gitleaks           : %s" % (shutil.which("gitleaks") or "not installed"))
    print("block threshold    : %d/10" % _block_threshold())
    if not installed:
        print("\nInstall with:  python3 %s --install --global" % ADAPTER)
    return 0


def main():
    a = sys.argv[1:]
    g = "--global" in a
    if "--staged" in a:
        return run_staged()
    if "--pre-push" in a:
        return run_pre_push()
    if "--install" in a:
        return install(g)
    if "--uninstall" in a:
        return uninstall(g)
    if "--status" in a:
        return status()
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
