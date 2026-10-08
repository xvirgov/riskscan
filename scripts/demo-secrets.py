#!/usr/bin/env python3
"""Show what the secrets surface prints, with and without the git hooks installed.

    python3 scripts/demo-secrets.py            # everything
    python3 scripts/demo-secrets.py agent      # just the PreToolUse layer
    python3 scripts/demo-secrets.py git        # just the pre-commit / pre-push layer

Builds throwaway repos under a temp dir and deletes them. The credentials are fake but
real-shaped — AWS's own documented example key id, and tokens with valid provider prefixes.

They are assembled from fragments at runtime rather than written out as literals. Not to evade
anything: this file is itself committed, riskscan scans it, and a literal here is a finding it
is right to report. Storing one would mean either a permanent false positive in our own repo or
widening `skip_paths` to cover `scripts/`, and neither is worth it for a demo fixture.

The hook state is forced in-process rather than read from your machine, so the comparison
is honest whatever your actual `core.hooksPath` says, and running this never changes it.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from riskscan import engine  # noqa: E402

_K = "KEY"
FAKE = {
    "aws": "AKIA" + "IOSFODNN7EXAMPLE",
    "gh": "ghp_" + "0123456789abcdefghijABCDEFGHIJ012345",
    "pem": ("-----BEGIN OPENSSH PRIVATE %s-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMw\n"
            "-----END OPENSSH PRIVATE %s-----\n") % (_K, _K),
}
BAR = "─" * 78


def hr(title):
    print("\n%s\n%s\n%s" % (BAR, title, BAR))


def mkrepo(files):
    d = tempfile.mkdtemp(prefix="riskscan-demo-")
    subprocess.run(["git", "init", "-q", d], check=True)
    for rel, content in files.items():
        p = os.path.join(d, rel)
        if os.path.dirname(p) and not os.path.isdir(os.path.dirname(p)):
            os.makedirs(os.path.dirname(p))
        with open(p, "w") as f:
            f.write(content)
    return d


def banner(cmd, cwd, hooks):
    """One PreToolUse verdict with the hook state forced."""
    real = engine.git_hooks_installed
    engine.git_hooks_installed = lambda c=None: hooks
    engine._HOOKS_CACHE.clear()
    try:
        r = engine.analyze(engine.make_action("command", command=cmd, cwd=cwd), engine.CONFIG)
        if r is None:
            return "(nothing to analyze)"
        colour = r["state"][0]
        if engine.CONFIG.get("quiet_safe") and colour == "green" and not r["skipped"]:
            return "(silent — nothing worth interrupting for)"
        out = engine.render_banner(r)
        thresh = engine.CONFIG.get("ask_threshold", 7)
        asks = r["findings"] and r["overall"] >= thresh
        return out + "\n   -> %s" % ("PROMPTS you at approval time" if asks
                                     else "no prompt; the analysis goes to the model only")
    finally:
        engine.git_hooks_installed = real
        engine._HOOKS_CACHE.clear()


def agent_layer():
    clean = mkrepo({"values.yaml": "replicas: 2\n"})
    secret = mkrepo({"deploy/.env": "AWS_ACCESS_KEY_ID=%s\nGH=%s\n" % (FAKE["aws"], FAKE["gh"]),
                     "deploy/id_ed25519": FAKE["pem"]})
    k8s = mkrepo({"sealed.yaml": "data:\n  id_rsa: %s\n" % __import__("base64").b64encode(
        FAKE["pem"].encode()).decode()})
    cases = [
        ("a routine commit, nothing to find", "git add -A && git commit -m 'bump replicas'", clean),
        ("a staged AWS key + GitHub token", "git add -A && git commit -m 'deploy cfg'", secret),
        ("an SSH private key", "git add deploy/id_ed25519", secret),
        ("a key hidden in a k8s Secret (base64)", "git add -A", k8s),
        ("a command that changes directory first", "cd /srv/app && git add -A", clean),
    ]
    try:
        for title, cmd, cwd in cases:
            hr(title)
            print("$ %s" % cmd)
            for hooks, label in ((False, "WITHOUT the git hooks"), (True, "WITH the git hooks")):
                print("\n  [%s]" % label)
                for ln in banner(cmd, cwd, hooks).splitlines():
                    print("  " + ln)
    finally:
        for d in (clean, secret, k8s):
            shutil.rmtree(d, ignore_errors=True)


def git_layer():
    """The authoritative layer: what git itself refuses, using real hooks in a real repo."""
    hook = os.path.join(ROOT, "adapters", "git_hook.py")
    remote = tempfile.mkdtemp(prefix="riskscan-demo-remote-")
    subprocess.run(["git", "init", "-q", "--bare", os.path.join(remote, "r.git")], check=True)
    d = mkrepo({"app.txt": "base\n"})

    def git(*args, **kw):
        env = dict(os.environ, GIT_AUTHOR_NAME="demo", GIT_AUTHOR_EMAIL="d@d",
                   GIT_COMMITTER_NAME="demo", GIT_COMMITTER_EMAIL="d@d", **kw.pop("env", {}))
        return subprocess.run(["git", "-C", d] + list(args), capture_output=True, text=True, env=env)

    try:
        git("remote", "add", "origin", os.path.join(remote, "r.git"))
        subprocess.run([sys.executable, hook, "--install"], cwd=d, capture_output=True)
        git("add", "app.txt")
        git("commit", "-m", "init", env={"RISKSCAN_SKIP": "1"})

        hr("pre-commit: a credential staged, working tree deliberately clean")
        with open(os.path.join(d, "conf.env"), "w") as f:
            f.write("line1\nGH=%s\nline3\n" % FAKE["gh"])
        git("add", "conf.env")
        with open(os.path.join(d, "conf.env"), "w") as f:
            f.write("line1\nline3\n")          # worktree no longer has it; the index does
        print("$ git commit -m conf        (grep of the working tree finds nothing)")
        p = git("commit", "-m", "conf")
        print((p.stderr or p.stdout).rstrip() + "\n   -> git exit %d" % p.returncode)

        hr("pre-push: a secret committed and then removed — still in the range")
        git("reset", "-q", "HEAD", "--", "conf.env")
        with open(os.path.join(d, "app.txt"), "w") as f:
            f.write("base\nTOKEN=%s\n" % FAKE["gh"])
        git("add", "app.txt")
        git("commit", "-m", "add token", env={"RISKSCAN_SKIP": "1"})
        with open(os.path.join(d, "app.txt"), "w") as f:
            f.write("base\nTOKEN=${FROM_VAULT}\n")
        git("add", "app.txt")
        git("commit", "-m", "move to vault", env={"RISKSCAN_SKIP": "1"})
        print("$ git push origin HEAD      (working tree is clean; history is not)")
        p = git("push", "origin", "HEAD:refs/heads/main")
        print((p.stderr or p.stdout).rstrip() + "\n   -> git exit %d" % p.returncode)

        hr("the bypass, for a false positive")
        print("$ RISKSCAN_SKIP=1 git push ...")
        p = git("push", "origin", "HEAD:refs/heads/main", env={"RISKSCAN_SKIP": "1"})
        print((p.stderr or p.stdout).rstrip() + "\n   -> git exit %d" % p.returncode)
    finally:
        shutil.rmtree(d, ignore_errors=True)
        shutil.rmtree(remote, ignore_errors=True)


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "agent"):
        print("\n### AGENT LAYER — advisory, runs before the command, scans proposed content")
        agent_layer()
    if which in ("all", "git"):
        print("\n\n### GIT LAYER — authoritative, runs inside the repo, blocks")
        git_layer()
    print("\n%s\nYour machine right now: hooks %s\n%s" % (
        BAR, "INSTALLED" if engine.git_hooks_installed(os.getcwd()) else "NOT installed", BAR))
