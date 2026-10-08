"""riskscan engine — runtime-agnostic risk scoring for a proposed agent action.

Takes a normalized action (a shell command, or a file write/edit), routes it to
whichever analyzers are enabled and available, and returns a scored report:
green (safe) / yellow (caution) / red (danger) / white (NOT ANALYZED).

"NOT ANALYZED" is first-class: the absence of a warning must never be read as
safe. This module knows nothing about any specific agent runtime — the mapping
from a runtime's tool call to an `action` lives in an adapter (see adapters/).
"""
import base64
import json
import math
import os
import re
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

# An agent hook may invoke us with a minimal PATH (no ~/.local/bin, no brew bin), so
# external analyzers wouldn't be found. Extend PATH with the usual install locations;
# both shutil.which() and subprocess inherit this.
_seen = os.environ.get("PATH", "").split(os.pathsep)
for _p in [os.path.expanduser("~/.local/bin"), "/opt/homebrew/bin", "/usr/local/bin",
           os.path.expanduser("~/go/bin")]:
    if os.path.isdir(_p) and _p not in _seen:
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _p
        _seen.append(_p)


def load_json(name, default):
    try:
        with open(os.path.join(HERE, name)) as f:
            return json.load(f)
    except Exception:
        return default


DEFAULT_CONFIG = load_json("config.default.json", {})
# A local config.json (gitignored) overrides the shipped default, so an install can enable/tune
# analyzers without editing the tracked default. Falls back to config.default.json when absent.
CONFIG = load_json("config.json", None) or DEFAULT_CONFIG
REGISTRY = load_json("analyzers.json", {})


# ── severity → 1..10, banner glyphs ──────────────────────────────────────────
def state_of(score):
    if score >= 7:
        return ("red", "\U0001F534", "DANGER")
    if score >= 4:
        return ("yellow", "\U0001F7E1", "CAUTION")
    return ("green", "\U0001F7E2", "SAFE")


NOT_ANALYZED = ("white", "⚪", "NOT ANALYZED")

# ── built-in rule pack (zero-dependency floor) ───────────────────────────────
SAFE_LEADERS = {
    "echo", "printf", "print", "cat", "ls", "pwd", "grep", "egrep", "rg", "fgrep",
    "head", "tail", "less", "more", "which", "whoami", "id", "date", "env",
    "printenv", "wc", "sort", "uniq", "cut", "awk", "true", "test", "sleep",
    "hostname", "uname", "df", "du", "ps", "top", "stat", "file", "tree", "jq", "yq",
}
SAFE_SUBCMDS = {
    "git": {"status", "log", "diff", "show", "branch", "remote", "config", "blame", "describe", "rev-parse"},
    "kubectl": {"get", "describe", "logs", "top", "explain", "api-resources", "version", "config"},
    "helm": {"list", "status", "get", "history", "search", "show", "version"},
    "docker": {"ps", "images", "logs", "inspect", "version"},
    "terraform": {"plan", "validate", "fmt", "show", "output", "version", "state"},
    "aws": None,  # handled by verb prefix below
}

# Built-in rule pack. Each rule is (regex, score 1-10, label): every matching rule
# contributes a finding and the highest score wins. This is a broadly-useful starter
# set — add your own or override these via custom_rules.json (see README), no code edit.
BASH_RULES = [
    # ── destructive filesystem / device ──
    (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", 10, "fork bomb"),
    (r"\bmkfs\b", 10, "filesystem format (mkfs)"),
    (r"\bdd\b[^\n]*\bof=/dev/", 10, "dd write to raw device"),
    (r">\s*/dev/(sd|nvme|disk|hd)", 10, "redirect to raw block device"),
    # ── power / remote code execution ──
    (r"\b(shutdown|reboot|halt|poweroff)\b", 7, "host power/shutdown"),
    (r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b", 8, "pipe remote script to shell (curl|sh)"),
    # ── version control ──
    (r"\bgit\s+push\b[^\n]*(--force\b|--force-with-lease\b|\s-f\b)", 8, "git force-push"),
    (r"\bgit\s+reset\s+--hard\b", 6, "git reset --hard (discards changes)"),
    # ── kubernetes ──
    (r"\bkubectl\b[^\n]*\bdelete\b", 7, "kubectl delete"),
    (r"\bkubectl\b[^\n]*\b(apply|patch|replace|edit|scale|cordon|drain|rollout)\b", 5, "kubectl mutate"),
    (r"\bhelm\b[^\n]*\b(uninstall|delete|rollback)\b", 7, "helm remove/rollback"),
    # ── infrastructure-as-code ──
    (r"\bterraform\b[^\n]*\bdestroy\b", 9, "terraform destroy"),
    (r"\bterraform\b[^\n]*\bapply\b", 6, "terraform apply"),
    # ── cloud destructive ops (AWS shown as the worked example; add gcloud/az the same way) ──
    (r"\baws\s+s3\s+(rb|rm)\b", 8, "aws s3 remove bucket/objects"),
    (r"\baws\s+s3\s+sync\b[^\n]*--delete\b", 7, "aws s3 sync --delete (removes remote files)"),
    (r"\baws\s+(rds|docdb|neptune)\s+delete-db", 9, "aws rds: delete database (data loss)"),
    (r"\baws\s+eks\s+delete-(cluster|nodegroup|fargate-profile)\b", 9, "aws eks: delete cluster/nodegroup"),
    (r"\baws\s+dynamodb\s+delete-table\b", 9, "aws dynamodb: delete table (data loss)"),
    (r"\baws\s+kms\s+(schedule-key-deletion|disable-key)\b", 9, "aws kms: key deletion/disable (data loss)"),
    (r"\baws\s+efs\s+delete-file-system\b", 9, "aws efs: delete filesystem (data loss)"),
    (r"\baws\s+secretsmanager\s+delete-secret\b", 8, "aws secretsmanager: delete secret"),
    (r"\baws\s+cloudformation\s+delete-stack\b", 8, "aws cloudformation: delete stack"),
    (r"\baws\s+ec2\s+terminate-instances\b", 8, "aws ec2: terminate instances"),
    (r"\baws\s+(elbv2|elb)\s+delete-(load-balancer|target-group)\b", 7, "aws elb: delete load balancer"),
    (r"\baws\s+iam\s+update-assume-role-policy\b", 8, "aws iam: change role trust policy (priv-esc vector)"),
    (r"\baws\s+iam\s+(create-access-key|create-user|create-login-profile)\b", 7, "aws iam: create credentials"),
    (r"\baws\s+iam\s+(attach-(user|group|role)-policy|put-(user|group|role)-policy|create-policy-version)\b", 7, "aws iam: grant permissions"),
    (r"\baws\s+iam\s+delete-(open-id-connect-provider|saml-provider)\b", 8, "aws iam: delete identity provider (breaks IRSA/federation)"),
    (r"\baws\s+iam\s+(delete-(role|user|group|policy|instance-profile|role-policy|user-policy|group-policy|login-profile|access-key)|detach-(role|user|group)-policy|remove-role-from-instance-profile)\b", 7, "aws iam: delete/detach principal or policy (breaks assuming workloads)"),
    (r"\baws\s+ec2\s+authorize-security-group-(ingress|egress)\b[^\n]*0\.0\.0\.0/0", 8, "aws ec2: open security group to 0.0.0.0/0"),
    (r"\baws\s+ec2\s+authorize-security-group-(ingress|egress)\b", 6, "aws ec2: modify security group"),
    (r"\baws\s+ec2\s+run-instances\b", 5, "aws ec2: launch instances (billable)"),
    (r"\baws\b[^\n]*\s(delete-|terminate-|deregister-)", 6, "aws destructive API call"),
    # ── databases ──
    (r"(?i)\b(drop|truncate)\s+(table|database|schema)\b", 9, "SQL DROP/TRUNCATE"),
    (r"(?i)\bdelete\s+from\b", 6, "SQL DELETE FROM"),
    # ── permissions & processes ──
    (r"\bchmod\s+-R\s+0?777\b", 6, "recursive chmod 777"),
    (r"\bchmod\s+0?777\b", 5, "chmod 777 (world-writable)"),
    (r"\bkill(all)?\b[^\n]*(-9|-KILL)\b", 4, "force kill process"),
    (r"\beval\b", 6, "eval (dynamic execution)"),
]

INSTALL_PATTERNS = [
    ("PyPI", r"\b(?:pip3?|python3?\s+-m\s+pip|uv\s+pip)\s+install\s+(.+)"),
    ("PyPI", r"\bpoetry\s+add\s+(.+)"),
    ("npm", r"\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+add)\s+(.+)"),
]

# inline code smuggled through the shell: python -c "...", node -e "..."
# group 2 = single-quoted body, group 3 = double-quoted body
INLINE_CODE = [
    ("python", r"\bpython[0-9.]*\s+(?:-[^\sc]\S*\s+)*-c\s+('([^']*)'|\"([^\"]*)\")"),
    ("js", r"\bnode\s+(?:-[^\se]\S*\s+)*(?:-e|--eval)\s+('([^']*)'|\"([^\"]*)\")"),
]

MANIFESTS = {
    "requirements.txt": "PyPI", "pyproject.toml": "PyPI", "poetry.lock": "PyPI",
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm",
}
LANG_BY_EXT = {
    ".py": "python", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".ts": "ts", ".tsx": "ts",
}


# ── normalized action → analysis targets ─────────────────────────────────────
def make_action(kind, command=None, file_path=None, content=None, cwd=None):
    """A runtime-neutral description of a proposed action.
    kind: "command" (a shell command) or "write" (create/modify a file).
    cwd: the directory the command would run in — needed to resolve what a
    `git add`/`commit`/`push` would actually put into version control."""
    return {"kind": kind, "command": command, "file_path": file_path,
            "content": content, "cwd": cwd}


def rm_score(cmd):
    if not re.search(r"\brm\s+(?:-\S+\s+)*(?:-\S*r|--recursive)", cmd):
        return None  # needs a recursive flag to be destructive at scale
    # catastrophic only when a root/home/glob target immediately follows rm + its flags
    catastrophic = re.search(
        r"\brm\s+(?:-\S+\s+)*(/(?:\s|/|\*|$)|~(?:/|\s|$)|\$HOME|/\*|--no-preserve-root)", cmd)
    return (10, "rm -rf targeting root/home/glob") if catastrophic else (7, "recursive force-delete (rm -r)")


def strip_pkgs(rest):
    out = []
    for t in rest.split():
        if t in ("&&", "||", ";", "|", "&"):
            break  # end of this command
        if t.startswith("-"):
            continue  # flag
        if re.search(r"[<>&]", t):
            break  # shell redirection (e.g. 2>&1) — not a package
        if not re.match(r"^[A-Za-z0-9@._/\-]+([=<>!~\[].*)?$", t):
            continue
        out.append(t)
    return out[:8]


def targets_from_action(action):
    """Expand a normalized action into analysis targets; each target carries what an analyzer needs."""
    targets = []
    kind = action.get("kind")
    if kind == "command":
        cmd = action.get("command") or ""
        targets.append({"surface": "bash", "command": cmd, "cwd": action.get("cwd")})
        for eco, pat in INSTALL_PATTERNS:
            for m in re.finditer(pat, cmd):
                pkgs = strip_pkgs(m.group(1))
                if pkgs:
                    targets.append({"surface": "deps", "ecosystem": eco, "packages": pkgs, "manifest": None, "persisted": False})
        for lang, pat in INLINE_CODE:
            for m in re.finditer(pat, cmd, re.DOTALL):
                code = m.group(2) if m.group(2) is not None else m.group(3)
                if code:
                    ext = "py" if lang == "python" else "js"
                    targets.append({"surface": lang, "content": code, "file_path": "inline." + ext, "inline": True})
        targets += _vcs_secret_targets(cmd, action.get("cwd"))
    elif kind == "write":
        fp = action.get("file_path") or ""
        content = action.get("content") or ""
        base = os.path.basename(fp)
        ext = os.path.splitext(fp)[1].lower()
        if content:
            # Any file can carry a credential, so this is not limited by extension — and it
            # catches the secret one step earlier than the git surface does.
            targets.append({"surface": "secrets", "mode": "write", "file_path": fp, "content": content})
        if base in MANIFESTS:
            targets.append({"surface": "deps", "ecosystem": MANIFESTS[base], "packages": [], "manifest": fp, "content": content, "persisted": True})
        lang = LANG_BY_EXT.get(ext)
        if lang:
            targets.append({"surface": lang, "file_path": fp, "content": content})
    return targets


# ── built-in analyzer ─────────────────────────────────────────────────────────
POLICY_LABEL = ("git: writes to version control and no authoritative scan is installed"
                " → riskscan --install-git-hooks")


def builtin_bash(cmd, cwd=None):
    findings = []
    max_score = 0
    for pat, score, label in BASH_RULES:
        if re.search(pat, cmd):
            findings.append((score, label))
            max_score = max(max_score, score)
    # Content entering version control with NOTHING downstream to check it is top-of-scale by
    # policy. Once the git hooks are installed that is no longer true — they block at commit and
    # push, inside the right tree, on the actual index — so the synthetic score would fire on
    # every routine commit while adding nothing. Same question as the ⚪ handoff, asked once.
    # Read-only git (status/log/diff/...) is unaffected; see SAFE_SUBCMDS.
    if any(rx.search(cmd) for _, rx in GIT_SECRET_CMDS) and not git_hooks_installed(cwd):
        sc = int(((CONFIG.get("secrets") or {}).get("unchecked_write_score", 10)))
        findings.append((sc, POLICY_LABEL))
        max_score = max(max_score, sc)
    rm = rm_score(cmd)
    if rm:
        findings.append(rm)
        max_score = max(max_score, rm[0])
    if re.search(r"\bsudo\b", cmd):
        findings.append((5, "runs with sudo (privilege escalation)"))
        max_score = max(max_score, 5)
    # a mutating/destructive aws call against the prod profile is higher stakes
    if max_score >= 5 and re.search(r"--profile[=\s]+prod(uction)?\b", cmd):
        max_score = min(10, max_score + 1)
        findings.append((max_score, "targets PROD profile"))
    # A '>' inside arithmetic $((..)), a [[..]] test, or process substitution <(..)/>(..) is a
    # comparison/redirection-of-a-subshell, not a file overwrite — blank those spans first.
    red_cmd = re.sub(r"\$\(\(.*?\)\)|\[\[.*?\]\]|[<>]\(.*?\)", "", cmd)
    if re.search(r"(^|[^0-9>])>\s*(?!/dev/null)[^\s>|&]", red_cmd) and max_score < 4:
        findings.append((4, "overwrites/creates a file (redirect)"))
        max_score = max(max_score, 4)
    if not findings:
        first = re.split(r"\s+", cmd.strip())[0] if cmd.strip() else ""
        first = os.path.basename(first)
        subs = re.split(r"\s+", cmd.strip())
        sub = subs[1] if len(subs) > 1 else ""
        is_safe = first in SAFE_LEADERS
        if not is_safe and first in SAFE_SUBCMDS:
            allowed = SAFE_SUBCMDS[first]
            if first == "aws":
                is_safe = bool(re.search(r"\baws\b[^\n]*\s(get-|describe-|list-|ls\b)", cmd))
            elif allowed and sub in allowed:
                is_safe = True
        if is_safe:
            return (1, [(1, "read-only / print")])
        return (2, [(2, "no known-dangerous pattern (builtin heuristic only)")])
    return (max_score, findings)


def builtin_deps(t):
    pkgs = ", ".join(t.get("packages") or []) or (t.get("manifest") or "manifest")
    return (2, [(2, "pulls dependency: %s" % pkgs)])


PY_RULES = [
    (r"\bos\.system\s*\(", 7, "os.system (shell execution)"),
    (r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True", 8, "subprocess shell=True"),
    (r"\bsubprocess\b", 5, "subprocess (spawns processes)"),
    (r"\bos\.popen\s*\(", 6, "os.popen (shell execution)"),
    (r"\b(eval|exec)\s*\(", 7, "eval/exec (dynamic code execution)"),
    (r"\b__import__\s*\(", 6, "__import__ (dynamic import)"),
    (r"\bpickle\.(loads?|Unpickler)\b", 6, "pickle load (deserialization RCE risk)"),
    (r"\bmarshal\.loads\b", 6, "marshal.loads (deserialization)"),
    (r"\byaml\.load\s*\((?![^)]*SafeLoader)", 6, "yaml.load without SafeLoader"),
    (r"\bctypes\b", 6, "ctypes (native memory/syscalls)"),
    (r"\bshutil\.rmtree\b", 6, "shutil.rmtree (recursive delete)"),
    (r"\bos\.(remove|unlink)\b", 4, "file delete"),
    (r"\bsocket\b", 3, "socket (raw network access)"),
    (r"\bbase64\b", 2, "base64 (often used to obfuscate payloads)"),
    (r"\b(requests?\.\w+\(|urllib)", 3, "outbound HTTP"),
    (r"\bopen\s*\([^)]*[\"'][wa]", 3, "writes a file"),
]

JS_RULES = [
    (r"child_process|\bexecSync\b|\bexec\s*\(", 7, "child_process (shell execution)"),
    (r"\beval\s*\(", 7, "eval (dynamic code execution)"),
    (r"new\s+Function\s*\(", 6, "new Function (dynamic code)"),
    (r"\bfs\.(unlink|rm|rmdir|rmSync)\b", 6, "filesystem delete"),
    (r"require\s*\(\s*[\"']https?", 4, "network require"),
    (r"\bprocess\.env\b", 3, "reads env (possible secret access)"),
]


# ── secrets: credential material about to be written or committed ────────────
# Two tiers on purpose. A token whose *shape* is unambiguous (cloud key id, PEM block,
# provider-prefixed token) scores 9 and will force the prompt; a generic high-entropy
# assignment scores 6, which informs the model without interrupting the user.
#
# A finding NEVER carries the matched text. The banner is echoed into the transcript,
# the hook log and the model's context, so printing the secret would create the very
# exposure this surface exists to prevent. Rule label + file + line, nothing else.
SECRET_RULES = [
    (r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", 9, "AWS access key id"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}", 9, "AWS secret access key"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", 9, "private key block"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 9, "GitHub token"),
    (r"\bgithub_pat_[A-Za-z0-9_]{30,}\b", 9, "GitHub fine-grained PAT"),
    (r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 9, "GitLab personal access token"),
    (r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b", 9, "Slack token"),
    (r"\bsk_live_[A-Za-z0-9]{20,}\b", 9, "Stripe live secret key"),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", 9, "Google API key"),
    (r"\bsk-(?:proj-|ant-api\d\d-)?[A-Za-z0-9_\-]{32,}\b", 9, "LLM provider API key"),
    (r"\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{40,}\b", 9, "SendGrid API key"),
    (r"\bhvs\.[A-Za-z0-9_\-]{24,}\b", 9, "Vault service token"),
    (r"\bdop_v1_[a-f0-9]{64}\b", 9, "DigitalOcean token"),
    (r"\bnpm_[A-Za-z0-9]{36}\b", 9, "npm access token"),
    (r"(?i)\"type\"\s*:\s*\"service_account\"", 8, "GCP service-account key material"),
    (r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:@/]+:[^\s:@/]{4,}@",
     8, "connection string with inline password"),
    (r"(?i)\bauthorization\s*[=:]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9_\-./+=]{16,}",
     7, "hardcoded Authorization header"),
    (r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 6, "JWT"),
]

# Generic `name = value` credentials, quoted or not — YAML and .env files usually leave the
# value bare, and the same credential must not score differently for its quoting. The name
# alone is never enough: randomness is what separates a token from `password = "changeme"`.
SECRET_ASSIGN = re.compile(
    r"(?i)\b([a-z0-9_\-.]*(?:pass(?:wd|word)?|secret|token|api[_\-]?key|apikey|access[_\-]?key"
    r"|client[_\-]?secret|private[_\-]?key|credentials?|auth[_\-]?key)[a-z0-9_\-.]*)"
    r"\s*[=:]\s*(?:[\"']([^\"'\n]{16,200})[\"']|([^\s\"'\n]{16,200}))")
_PLACEHOLDER = re.compile(
    r"(?i)^(?:\$|\{\{|<|%|x{4,}|\*{4,}|redacted|changeme|change[_\-]?me|example|placeholder"
    r"|dummy|sample|fake|test|your|insert|todo|tbd|none|null|n/?a|secret|password|token)")
_TEMPLATED = re.compile(r"\$\{|\{\{|\$\(|<%|%\(|\$[A-Z_]{3,}")

# Volume limits: this surface can be handed a whole changeset, and the hook is synchronous.
SECRET_MAX_FILES = 40
SECRET_MAX_BYTES = 256 * 1024
SECRET_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".jar", ".war", ".whl", ".so", ".dylib", ".dll", ".o", ".a", ".class",
    ".pyc", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mov", ".mp3", ".wav", ".parquet", ".db",
}
# Paths skipped on the git surface only (not on a single-file write): fixture and vendored
# trees are where a changeset's false positives come from. Tunable via config "secrets".
SECRET_SKIP_PATHS = [
    r"(^|/)\.git/",
    r"(^|/)(tests?|testdata|fixtures?|__snapshots__|vendor|node_modules|\.venv|venv|dist|build)/",
    r"\.(example|sample|dist|template|tpl)(\.|$)",
    r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|go\.sum|Cargo\.lock)$",
]

# ── what a git command is about to put into version control ──────────────────
# At PreToolUse time nothing is staged yet, so `gitleaks protect --staged` has nothing to
# look at: the candidate file set has to be derived from the working tree instead. Keys are
# tried in this order and the first match wins — in an `add && commit && push` chain the
# staging step is the broadest read of the new content.
_GIT_PRE = (r"(?:-C\s+\S+\s+|-c\s+\S+\s+|--no-pager\s+|--git-dir[=\s]\S+\s+"
            r"|--work-tree[=\s]\S+\s+)*")
GIT_SECRET_CMDS = [
    ("add", re.compile(r"\bgit\s+" + _GIT_PRE + r"add\b")),
    ("worktree", re.compile(r"\bgit\s+" + _GIT_PRE + r"commit\b[^\n|;&]*?(?:\s--all\b|\s-[A-Za-z]*a)")),
    ("staged", re.compile(r"\bgit\s+" + _GIT_PRE + r"commit\b")),
    ("push", re.compile(r"\bgit\s+" + _GIT_PRE + r"push\b")),
]
GIT_SECRET_LABEL = {"add": "staged", "worktree": "commit -a", "staged": "staged", "push": "push"}


def _git_out(cwd, args, timeout=10):
    """Run a read-only git command in cwd; stdout on success, None on any failure."""
    try:
        p = subprocess.run(["git", "-C", cwd] + args, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    return p.stdout if p.returncode == 0 else None


def _add_pathspecs(cmd):
    """Explicit pathspecs on a `git add`, so git resolves those rather than the whole tree."""
    m = re.search(r"\bgit\s+" + _GIT_PRE + r"add\b(.*)", cmd)
    if not m:
        return []
    out = []
    for tok in m.group(1).split():
        if tok in ("&&", "||", ";", "|", "&"):
            break
        if tok == "--" or tok.startswith("-"):
            continue
        if re.search(r"[<>$`*?\[\]]", tok):
            return []  # glob or substitution — ask git about the whole tree instead
        out.append(tok.strip("'\""))
    return out[:20]


def _git_candidates(cwd, key, cmd):
    """(paths, None, base) about to enter git, or (None, reason, None) when unknowable.

    git prints these paths relative to the repository ROOT, not to the directory it ran in,
    so `base` is the toplevel — joining against `cwd` silently breaks whenever the agent is
    working in a subdirectory, which is most of the time.
    """
    if not cwd or not os.path.isdir(cwd):
        return (None, "no working directory to resolve the changeset in", None)
    if _git_out(cwd, ["rev-parse", "--git-dir"]) is None:
        return (None, "not a git repository", None)
    top = _git_out(cwd, ["rev-parse", "--show-toplevel"])
    base = top.strip() if top and top.strip() else cwd
    filt = ["--diff-filter=ACMR", "--name-only"]  # added/copied/modified/renamed — content that lands
    if key == "add":
        specs = _add_pathspecs(cmd)
        out = _git_out(cwd, ["add", "-n", "--"] + specs) if specs else _git_out(cwd, ["add", "-n", "-A"])
        if out is None:
            return (None, "`git add -n` failed (ignored or unmatched pathspec)", None)
        return ([m.group(1) for m in re.finditer(r"^add '(.*)'$", out, re.M)], None, base)
    if key == "worktree":
        out = _git_out(cwd, ["diff"] + filt)
    elif key == "staged":
        out = _git_out(cwd, ["diff", "--cached"] + filt)
    else:  # push — the commits not yet on the upstream branch
        up = _git_out(cwd, ["rev-parse", "--abbrev-ref", "@{upstream}"])
        if not up:
            return (None, "branch has no upstream — cannot tell which commits would be pushed", None)
        out = _git_out(cwd, ["diff"] + filt + ["%s..HEAD" % up.strip()])
    if out is None:
        return (None, "`git diff` failed", None)
    return ([ln for ln in out.splitlines() if ln.strip()], None, base)


def _git_dir_override(cmd):
    """Where a `git -C <path>` points: "" for none, None when git is aimed somewhere we
    cannot follow. Resolving the wrong tree would be worse than not resolving one at all —
    it reads as a green for a changeset nobody looked at."""
    m = re.search(r"\bgit\s+(.*)", cmd)
    if not m:
        return ""
    toks, out, i = m.group(1).split(), "", 0
    while i < len(toks):
        t = toks[i]
        if t == "-C" and i + 1 < len(toks):
            out = toks[i + 1].strip("'\"")
            i += 2
            continue
        if t.startswith("--git-dir") or t.startswith("--work-tree"):
            return None
        if t.startswith("-"):
            i += 1
            continue
        break  # first non-flag token is the subcommand
    return out


# A `cd`/`pushd` ahead of the git command used to be predicted here — following literal paths,
# expanding variables, refusing substitutions. That prediction is unbounded (subshells, `env -C`,
# $PWD games, symlinked repos) and every gap in it is a silent false green, so it is no longer
# attempted: the command hands off to the git hook, which git runs *inside* the right tree.
_CD_RE = re.compile(r"^(?:cd|pushd|popd)\b")


def _has_cd(cmd):
    """True when a directory change may precede the git command, making the target tree a guess."""
    # Checked before the segment walk: a subshell or `env -C` is not a segment of its own, so
    # walking to the git command would return "no cd" and resolve the caller's tree instead.
    if re.search(r"\(\s*(?:cd|pushd)\s|\benv\s+(?:-\S+\s+)*-C[=\s]", cmd):
        return True
    for seg in re.split(r"&&|\|\||;", cmd):
        seg = seg.strip().lstrip("({ ")
        if re.search(r"\bgit\s", seg):
            return False
        if _CD_RE.match(seg):
            return True
    return False


HOOK_MARKER = "# >>> riskscan >>>"


_HOOKS_CACHE = {}


def git_hooks_installed(cwd=None):
    """True when riskscan's own git hooks are in place, making them the authoritative scan.

    The ⚪ handoff note is suppressed when they are: naming a gap that something else covers
    is noise, not fail-loud. When they are absent the note carries an install hint instead,
    exactly as a missing analyzer does.
    """
    key = cwd or ""
    if key in _HOOKS_CACHE:
        return _HOOKS_CACHE[key]
    paths = []
    gp = _git_out(cwd or os.getcwd(), ["config", "--get", "core.hooksPath"]) if cwd else None
    if gp and gp.strip():
        paths.append(os.path.expanduser(gp.strip()))
    paths.append(os.path.expanduser("~/.githooks"))
    if cwd:
        paths.append(os.path.join(cwd, ".git", "hooks"))
    for d in paths:
        f = os.path.join(d, "pre-commit")
        try:
            with open(f) as fh:
                if HOOK_MARKER in fh.read():
                    _HOOKS_CACHE[key] = True
                    return True
        except Exception:
            continue
    _HOOKS_CACHE[key] = False
    return False


def _vcs_secret_targets(cmd, cwd):
    """A `secrets` target for a command that moves content into version control."""
    key = next((k for k, rx in GIT_SECRET_CMDS if rx.search(cmd)), None)
    if key is None:
        return []
    cwd = cwd or os.getcwd()

    def unresolved(note):
        """⚪ when nothing else covers this, silence when the git hook does.

        Fail-loud means naming what was not checked — not repeating it once an authoritative
        scan is in place. With the hooks installed, every one of these cases is scanned at
        commit time inside the right tree, so the note would be noise rather than a warning.
        """
        if git_hooks_installed(cwd):
            return []
        return [{"surface": "secrets", "mode": "vcs", "key": key, "cwd": cwd,
                 "files": None, "note": note}]

    if _has_cd(cmd):
        return unresolved("command changes directory first — the tree is not resolved here"
                          " → riskscan --install-git-hooks")
    override = _git_dir_override(cmd)
    if override is None:
        return unresolved("command redirects git with --git-dir/--work-tree — the tree is not "
                          "resolved here → riskscan --install-git-hooks")
    if override:
        cwd = override if os.path.isabs(override) else os.path.join(cwd, override)
    files, note, base = _git_candidates(cwd, key, cmd)
    if files is None:
        return unresolved(note or "the changeset could not be resolved")
    return [{"surface": "secrets", "mode": "vcs", "key": key, "cwd": base or cwd,
             "files": files, "note": note}]


def _entropy(s):
    """Shannon entropy in bits/char — a proxy for "is this value random"."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _looks_random(value):
    """A credential-shaped value — not a placeholder, a reference, a URI or an identifier."""
    if _PLACEHOLDER.match(value) or _TEMPLATED.search(value):
        return False  # a placeholder, or a reference resolved elsewhere (env/vault/helm)
    if re.match(r"^[a-z][a-z0-9+.\-]*://", value) or re.match(r"^[~./]", value):
        return False  # a URI or path; credentials *inside* a URI have their own rule
    if re.match(r"^[a-f0-9]+$", value) or value.isdigit():
        return False  # a hash or id — costs a few real hex keys, kills integrity-digest noise
    classes = sum(bool(re.search(c, value)) for c in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3 and _entropy(value) < 4.5:
        return False  # kebab-case slugs (`my-app-tls-secret`) read as text, not key material
    return _entropy(value) >= 4.0


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")


def _b64_spans(text, limit=8):
    """Decoded payloads of base64-looking runs. Kubernetes Secrets, sealed manifests and CI
    variables carry key material this way, and every plaintext rule is blind to it."""
    out = []
    for m in _B64_RUN.finditer(text):
        if len(out) >= limit:
            break
        blob = m.group(0)
        if len(blob) > 200000:
            continue
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except Exception:
            continue
        if b"\0" in raw[:4000]:
            continue
        dec = raw.decode("utf-8", "replace")[:200000]
        head = dec[:4000]
        if head and sum(1 for c in head if c.isprintable() or c in "\n\r\t") / float(len(head)) > 0.9:
            out.append((m.start(), dec))
    return out


def _secret_scan(text, where=""):
    """(score, findings) for one blob. Location-only reporting — see SECRET_RULES."""
    if not text:
        return (0, [])
    hits = {}  # label -> (score, first line, count)

    def note(label, score, start):
        line = text.count("\n", 0, start) + 1
        prev = hits.get(label)
        hits[label] = (score, prev[1] if prev else line, (prev[2] if prev else 0) + 1)

    for pat, score, label in SECRET_RULES:
        for m in re.finditer(pat, text):
            note(label, score, m.start())
    for m in SECRET_ASSIGN.finditer(text):
        if _looks_random(m.group(2) or m.group(3) or ""):
            note("high-entropy value assigned to `%s`" % m.group(1).lower()[:40], 6, m.start())
    # Same rules over anything base64 hid from them, reported at the encoded blob's line.
    for start, dec in _b64_spans(text):
        for pat, score, label in SECRET_RULES:
            if re.search(pat, dec):
                note(label + " (base64-encoded)", score, start)
        for m in SECRET_ASSIGN.finditer(dec):
            if _looks_random(m.group(2) or m.group(3) or ""):
                note("high-entropy value assigned to `%s` (base64-encoded)"
                     % m.group(1).lower()[:40], 6, start)
    findings = []
    for label, (score, line, count) in hits.items():
        loc = "%s:%d" % (where, line) if where else "line %d" % line
        findings.append((score, "%s — %s%s" % (label, loc, " (+%d more)" % (count - 1) if count > 1 else "")))
    findings.sort(key=lambda f: -f[0])
    return (max((f[0] for f in findings), default=0), findings)


def _secret_skip(path, patterns):
    low = path.replace("\\", "/")
    if os.path.splitext(low)[1].lower() in SECRET_SKIP_EXT:
        return True
    return any(re.search(p, low) for p in patterns)


def _read_text(path):
    """File contents as text, or None when it is binary, oversized or unreadable."""
    try:
        if os.path.getsize(path) > SECRET_MAX_BYTES:
            return None
        with open(path, "rb") as f:
            raw = f.read()
    except Exception:
        return None
    if b"\0" in raw[:8000]:
        return None
    return raw.decode("utf-8", "replace")


def builtin_secrets(t, config=None):
    """Scan content about to be written, or committed/pushed, for credential material.

    Returns (score, findings, notes). `score` is None when the content could not be
    determined at all, so the caller surfaces ⚪ NOT ANALYZED rather than a green;
    `notes` are partial-coverage reasons shown even alongside real findings.
    """
    if t.get("mode") == "write":
        sc, fs = _secret_scan(t.get("content") or "", os.path.basename(t.get("file_path") or ""))
        return (sc, fs, []) if fs else (1, [(1, "no credential pattern in the written content")], [])

    items, notes = _secret_file_set(t, config)
    if items is None:
        return (None, [], notes)
    where = GIT_SECRET_LABEL.get(t.get("key"), "git")
    hits, worst = [], 0
    for rel, text in items:
        sc, fs = _secret_scan(text, rel)
        if fs:
            worst = max(worst, sc)
            hits += fs
    if not hits:
        return (1, [(1, "no credential pattern in %d file(s) to %s" % (len(items), where))], notes)
    shown = hits[:6] + ([(1, "+%d more location(s)" % (len(hits) - 6))] if len(hits) > 6 else [])
    return (worst, [(s, "%s (%s)" % (lbl, where)) for s, lbl in shown], notes)


def _secret_file_set(t, config=None):
    """((relpath, text) for each file in the changeset, notes), or (None, notes) when the
    changeset is unknowable. Shared by every `secrets` analyzer so they all see exactly the
    same slice and produce the same ⚪ reasons — two analyzers disagreeing about *which files*
    they looked at would make the banner unreadable."""
    files = t.get("files")
    if files is None:
        return (None, [t.get("note") or "could not determine which files would be committed"])
    cfg = (config or {}).get("secrets") or {}
    skips = cfg.get("skip_paths", SECRET_SKIP_PATHS)
    cap = int(cfg.get("max_files", SECRET_MAX_FILES))
    cwd = t.get("cwd") or ""
    items, notes, unreadable, missing = [], [], [], []
    for i, rel in enumerate(files):
        if _secret_skip(rel, skips):
            continue
        if len(items) >= cap:
            notes.append("%d of %d file(s) past the %d-file scan cap — not scanned"
                         % (len(files) - i, len(files), cap))
            break
        full = os.path.join(cwd, rel)
        if not os.path.isfile(full):
            missing.append(rel)
            continue
        text = _read_text(full)
        if text is None:
            unreadable.append(rel)
            continue
        items.append((rel, text))
    if unreadable:
        notes.append("%d file(s) unreadable as text (binary or >%dKB): %s"
                     % (len(unreadable), SECRET_MAX_BYTES // 1024, ", ".join(unreadable[:3])))
    if missing:
        notes.append("%d file(s) git listed could not be located under %s: %s"
                     % (len(missing), cwd or "?", ", ".join(missing[:3])))
    return (items, notes)


def _load_custom_rules():
    """Merge user rules from custom_rules.json (if present), so adding a rule needs no code edit.

    Format: {"bash": [["regex", 7, "label"], ...], "python": [...], "js": [...], "secrets": [...]}.
    Rules are appended to the built-in packs; since the highest score wins, a custom rule can
    only *raise* an action's score, never mask a built-in one. Bad entries are skipped, never fatal.
    """
    data = load_json("custom_rules.json", {})

    def conv(items):
        out = []
        for item in items or []:
            try:
                rx, score, label = item[0], int(item[1]), str(item[2])
                re.compile(rx)  # reject an invalid regex rather than crash the hook
                out.append((rx, score, label))
            except Exception:
                continue
        return out

    return (conv(data.get("bash")), conv(data.get("python")), conv(data.get("js")),
            conv(data.get("secrets")))


_custom_bash, _custom_py, _custom_js, _custom_secrets = _load_custom_rules()
BASH_RULES += _custom_bash
PY_RULES += _custom_py
JS_RULES += _custom_js
SECRET_RULES += _custom_secrets


def _rule_scan(code, rules, empty_label):
    findings = []
    mx = 0
    for pat, score, label in rules:
        if re.search(pat, code):
            findings.append((score, label))
            mx = max(mx, score)
    # combination smell: process control + network + obfuscation = reverse-shell/malware
    proc = re.search(r"subprocess|os\.system|os\.popen|child_process|\bexec\b|\beval\b", code)
    net = re.search(r"\bsocket\b|requests|urllib|https?", code)
    obf = re.search(r"\bbase64\b|\bctypes\b|\bmarshal\b|atob\(", code)
    if proc and net and obf:
        findings.append((9, "process + network + obfuscation together (reverse-shell/malware fingerprint)"))
        mx = max(mx, 9)
    elif proc and net:
        findings.append((8, "spawns processes AND opens network (backdoor/exfiltration pattern)"))
        mx = max(mx, 8)
    if not findings:
        return (2, [(2, empty_label)])
    return (mx, findings)


def builtin_python(code):
    return _rule_scan(code or "", PY_RULES, "no known-dangerous Python pattern (builtin heuristic only)")


def builtin_js(code):
    return _rule_scan(code or "", JS_RULES, "no known-dangerous JS pattern (builtin heuristic only)")


# ── external analyzers ────────────────────────────────────────────────────────
def clamp(n):
    return max(1, min(10, int(n)))


def parse_shguard(out):
    """sh-guard (github.com/aryanbhosale/sh-guard) classify() → {score:0-100, level,
    reason, risk_factors:[str], mitre_mappings:[{technique_id}]}. Maps 0-100 → 1-10."""
    try:
        d = json.loads(out)
    except Exception:
        return None
    if not isinstance(d, dict) or d.get("error"):
        return None  # shim import/exec failure → treat as skip, not a finding
    raw = d.get("score")
    if isinstance(raw, (int, float)):
        sc = clamp(round(raw / 10.0))  # sh-guard scores 0-100
    else:
        lvl = str(d.get("level", "")).lower()
        sc = {"safe": 1, "low": 3, "caution": 4, "moderate": 5, "medium": 5,
              "high": 8, "danger": 8, "critical": 10}.get(lvl)
        if sc is None:
            return None
    label = d.get("reason") or (d.get("risk_factors") or ["sh-guard finding"])[0]
    mitre = d.get("mitre_mappings") or []
    if mitre and isinstance(mitre[0], dict) and mitre[0].get("technique_id"):
        label = "%s [MITRE %s]" % (label, mitre[0]["technique_id"])
    return (sc, [(sc, str(label))])


# CVSS v3.x base-metric values (first.org spec). OSV emits a CVSS *vector*, rarely a plain
# label — so we compute the real base score from the vector, then bucket it into our bands.
_CVSS3_M = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss3_base(vector):
    """CVSS v3.x base score (0.0–10.0) from a vector string; None if not a parseable v3 vector."""
    try:
        p = dict(x.split(":", 1) for x in vector.split("/") if ":" in x)
        changed = p.get("S") == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.50 if changed else 0.27}[p["PR"]]
        expl = 8.22 * _CVSS3_M["AV"][p["AV"]] * _CVSS3_M["AC"][p["AC"]] * pr * _CVSS3_M["UI"][p["UI"]]
        iss = 1 - (1 - _CVSS3_M["C"][p["C"]]) * (1 - _CVSS3_M["I"][p["I"]]) * (1 - _CVSS3_M["A"][p["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if changed else (6.42 * iss)
        if impact <= 0:
            return 0.0
        raw = (1.08 * (impact + expl)) if changed else (impact + expl)
        return min(math.ceil(raw * 10) / 10.0, 10.0)  # CVSS "roundup" = ceil to 1 decimal
    except Exception:
        return None


# CVSS qualitative band → riskscan 1-10. Capped at 9: a CVE's *presence* is not proof its
# vulnerable path is reachable, so no lone CVE earns the 10 reserved for confirmed catastrophe.
_SEV_TO_SCORE = {"critical": 9, "high": 8, "moderate": 6, "medium": 6, "low": 4}


def _cvss_band(base):
    if base >= 9.0:
        return "critical"
    if base >= 7.0:
        return "high"
    if base >= 4.0:
        return "moderate"
    if base > 0:
        return "low"
    return "unknown"


def _vuln_severity(v):
    """(label, score) for one OSV vuln, preferring a computed CVSS base score over the coarse label."""
    for s in (v.get("severity") or []):
        if str(s.get("type", "")).startswith("CVSS_V3"):
            base = _cvss3_base(s.get("score", ""))
            if base is not None:
                band = _cvss_band(base)
                return (band, _SEV_TO_SCORE.get(band, 6))
    # CVSS_V4-only or no vector → fall back to the label OSV sometimes carries
    label = str((v.get("database_specific") or {}).get("severity", "")).lower()
    if label in _SEV_TO_SCORE:
        return (label, _SEV_TO_SCORE[label])
    return ("unknown", 6)  # flagged but unscored → medium, never silently 0


def parse_osv(out):
    try:
        d = json.loads(out)
    except Exception:
        return None
    ids, worst, worst_sev = [], 0, "unknown"
    for res in d.get("results", []):
        for pkg in res.get("packages", []):
            for v in pkg.get("vulnerabilities", []):
                ids.append(v.get("id", "?"))
                sev, s = _vuln_severity(v)
                if s > worst:
                    worst, worst_sev = s, sev
    if not ids:
        return (1, [(1, "no known CVEs")])
    uniq = sorted(set(ids))
    shown = ", ".join(uniq[:5]) + (" …" if len(uniq) > 5 else "")
    return (worst, [(worst, "%d known CVE(s) [worst: %s]: %s" % (len(uniq), worst_sev.upper(), shown))])


def parse_generic_findings(out, key, sev_map, default):
    try:
        d = json.loads(out)
    except Exception:
        return None
    items = d.get(key, []) if isinstance(d, dict) else []
    if not items:
        return (1, [(1, "no findings")])
    top = max((sev_map.get(str(i.get("severity", i.get("issue_severity", ""))).lower(), default) for i in items), default=default)
    return (clamp(top), [(clamp(top), "%d finding(s)" % len(items))])


def _manifest_for(t):
    """(filename, content) for osv — osv picks its parser by basename, so the name matters."""
    if t.get("manifest"):
        name = os.path.basename(t["manifest"])
        content = t.get("content")
        if content is None:
            try:
                with open(t["manifest"]) as f:
                    content = f.read()
            except Exception:
                return (None, None)
        return (name, content)
    pkgs = t.get("packages") or []
    if not pkgs:
        return (None, None)
    if t.get("ecosystem") == "npm":
        deps = {}
        for p in pkgs:
            if "@" in p.lstrip("@"):
                n, v = p.rsplit("@", 1)
                deps[n] = v
            else:
                deps[p] = "*"
        return ("package.json", json.dumps({"dependencies": deps}))
    return ("requirements.txt", "\n".join(pkgs) + "\n")  # PyPI default


def run_external(name, spec, t):
    """Returns ('ok', score, findings) | ('skip', reason, install_hint)."""
    if not shutil.which(spec.get("detect", name)):
        return ("skip", "not installed", _install_hint(spec))
    needs = spec.get("needs")
    tmpdir = None
    try:
        subst = dict(t)
        if needs == "manifest":
            fname, content = _manifest_for(t)
            if fname is None:
                return ("skip", "nothing to audit (no packages/manifest)", "")
            if fname in spec.get("no_extractor", []):
                return ("skip", "%s is a manifest, not a pinned lockfile — no CVE extractor (commit a lockfile for CVE coverage)" % fname, "")
            tmpdir = tempfile.mkdtemp()
            path = os.path.join(tmpdir, fname)
            with open(path, "w") as f:
                f.write(content or "")
            subst["manifest"] = path
        elif needs == "file":
            ext = os.path.splitext(t.get("file_path", "code.py"))[1] or ".py"
            tmpdir = tempfile.mkdtemp()
            path = os.path.join(tmpdir, "code" + ext)
            with open(path, "w") as f:
                f.write(t.get("content", "") or "")
            subst["file"] = path
        argv = [_fmt(a, subst) for a in spec["run"]]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=40)
        parser = {"shguard": parse_shguard, "osv": parse_osv,
                  "bandit": lambda o: parse_generic_findings(o, "results", {"high": 8, "medium": 5, "low": 3}, 5)}[spec["parse"]]
        parsed = parser(proc.stdout)
        if parsed is None:
            return ("skip", "unparseable output", _install_hint(spec))
        return ("ok", parsed[0], parsed[1])
    except subprocess.TimeoutExpired:
        return ("skip", "timed out", "")
    except Exception as e:
        return ("skip", "error: %s" % e, "")
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


GD_ECO = {"PyPI": "pypi", "npm": "npm"}
# GuardDog rule taxonomy: threat-* = active malicious pattern; capability-* = merely possible
# (common in legit packages); metadata rules (typosquat/authorship) sit in between.
GD_CRIT = ("reverse-shell", "exfil", "download-exec", "dependency-confusion",
           "preinstall", "destruction", "cryptomining", "injection", "filesystem-read")


def _gd_rule_score(rule):
    r = rule.lower()
    if "typosquat" in r:
        return 9
    if r.startswith("threat-"):
        return 9 if any(k in r for k in GD_CRIT) else 8
    if r.startswith("capability-"):
        return 4  # a capability alone (network, filesystem) is common in legitimate packages
    return 6  # metadata / authorship heuristics


def _gd_result(out, pkg=""):
    """Parse a guarddog scan/verify JSON blob. results = {rule: [] | {}}; empty bucket = no match.
    Capability-only hits are summarized (low signal); threat/typosquat hits are surfaced."""
    try:
        d = json.loads(out or "{}")
    except Exception:
        return ("skip", "unparseable output", "")
    records = d if isinstance(d, list) else [d]
    findings, worst, caps = [], 0, 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = os.path.basename(str(rec.get("package", pkg) or pkg)) or "pkg"
        for rule, hits in (rec.get("results", {}) or {}).items():
            if not hits:  # {} or [] → rule did not match
                continue
            score = _gd_rule_score(rule)
            if score <= 4:
                caps += 1
                continue
            findings.append((score, "%s: %s" % (name, rule)))
            worst = max(worst, score)
    if caps and not findings:
        return ("ok", 4, [(4, "%s: %d capability signal(s), no threat pattern" % (pkg or "pkg", caps))])
    if not findings:
        return ("ok", 1, [(1, "no malicious indicators" + ((" (%s)" % pkg) if pkg else ""))])
    if caps:
        findings.append((4, "+%d capability signal(s)" % caps))
    return ("ok", worst, findings)


def run_guarddog(spec, t):
    gd = shutil.which(spec.get("detect", "guarddog"))
    if not gd:
        return ("skip", "not available (needs Python 3.10+)", _install_hint(spec))
    eco = GD_ECO.get(t.get("ecosystem"))
    if not eco:
        return ("skip", "ecosystem unsupported by guarddog", "")
    try:
        if t.get("manifest"):
            fname, content = _manifest_for(t)
            if fname is None:
                return ("skip", "nothing to verify", "")
            tmpdir = tempfile.mkdtemp()
            try:
                path = os.path.join(tmpdir, fname)
                with open(path, "w") as f:
                    f.write(content or "")
                proc = subprocess.run([gd, eco, "verify", path, "--output-format", "json"],
                                      capture_output=True, text=True, timeout=90)
                return _gd_result(proc.stdout)
            finally:
                shutil.rmtree(tmpdir, ignore_errors=True)
        allf, worst = [], 0
        for p in (t.get("packages") or [])[:5]:
            name = re.split(r"[=<>!~@\[]", p, 1)[0].strip()
            if not name:
                continue
            proc = subprocess.run([gd, eco, "scan", name, "--output-format", "json"],
                                  capture_output=True, text=True, timeout=90)
            r = _gd_result(proc.stdout, name)
            if r[0] == "ok":
                worst = max(worst, r[1])
                allf += [f for f in r[2] if f[0] > 1]
        if not allf:
            return ("ok", 1, [(1, "no malicious indicators")])
        return ("ok", worst, allf)
    except subprocess.TimeoutExpired:
        return ("skip", "timed out", "")
    except Exception as e:
        return ("skip", "error: %s" % e, "")


# gitleaks has no mode for "files that *would* be staged" — `--staged` reads the index, which is
# still empty at PreToolUse time. So we materialize the resolved changeset into a tempdir and use
# `gitleaks dir`, which also makes the write surface and all four git keys take one code path.
# `--redact` is not optional: it keeps the credential out of the report, and therefore out of this
# process, the banner and the model's context. Exit status 1 means "leaks found", not "failed".
GL_GENERIC = 6  # entropy-driven rules — same tier as the builtin's generic assignment rule


def _gl_score(rule_id):
    r = (rule_id or "").lower()
    if "private-key" in r or "private_key" in r:
        return 9
    if r.startswith("generic"):
        return GL_GENERIC
    return 9  # a named provider rule is a specific credential shape, like the builtin's tier-1


def parse_gitleaks(out):
    """gitleaks JSON report → (score, findings). Reads RuleID/File/StartLine only: `Secret` and
    `Match` carry the credential itself and must never reach a finding."""
    try:
        d = json.loads(out or "[]")
    except Exception:
        return None
    if not isinstance(d, list):
        return None
    if not d:
        return (1, [(1, "no findings")])
    hits, worst = [], 0
    for f in d:
        if not isinstance(f, dict):
            continue
        rid = str(f.get("RuleID") or "secret")
        score = _gl_score(rid)
        worst = max(worst, score)
        rel = str(f.get("File") or "?")
        hits.append((score, "%s — %s:%s" % (rid, rel, f.get("StartLine", "?"))))
    if not hits:
        return (1, [(1, "no findings")])
    hits.sort(key=lambda h: -h[0])
    shown = hits[:6] + ([(1, "+%d more location(s)" % (len(hits) - 6))] if len(hits) > 6 else [])
    return (worst, shown)


def run_gitleaks(spec, t, config=None):
    gl = shutil.which(spec.get("detect", "gitleaks"))
    if not gl:
        return ("skip", "not installed", _install_hint(spec))
    if t.get("mode") == "write":
        name = os.path.basename(t.get("file_path") or "") or "file.txt"
        items, notes = [(name, t.get("content") or "")], []
    else:
        items, notes = _secret_file_set(t, config)
        if items is None:
            return ("skip", notes[0] if notes else "changeset unknown", "")
    if not items:
        return ("ok", 1, [(1, "no findings")])
    tmpdir = tempfile.mkdtemp()
    try:
        for rel, text in items:
            dest = os.path.normpath(os.path.join(tmpdir, rel))
            if not dest.startswith(tmpdir + os.sep):
                continue  # a path escaping the tempdir is not something we copy
            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            with open(dest, "w") as f:
                f.write(text)
        proc = subprocess.run([gl, "dir", tmpdir, "-f", "json", "-r", "-",
                               "--no-banner", "--redact"],
                              capture_output=True, text=True, timeout=60)
        if proc.returncode not in (0, 1):  # 1 == leaks found
            return ("skip", "exited %d" % proc.returncode, "")
        parsed = parse_gitleaks(proc.stdout.replace(tmpdir + os.sep, ""))
        if parsed is None:
            return ("skip", "unparseable output", _install_hint(spec))
        return ("ok", parsed[0], parsed[1])
    except subprocess.TimeoutExpired:
        return ("skip", "timed out", "")
    except Exception as e:
        return ("skip", "error: %s" % e, "")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _fmt(arg, subst):
    for k, v in subst.items():
        arg = arg.replace("{%s}" % k, str(v))
    return arg


def _install_hint(spec):
    inst = spec.get("install", {})
    if not inst:
        return ""
    k = next(iter(inst))
    return inst[k]


# ── orchestration ─────────────────────────────────────────────────────────────
def analyze(action, config=None, registry=None):
    """Run enabled+available analyzers over a normalized action.

    Returns a report dict {surfaces, findings, skipped, overall, state} or None if
    the action has nothing to analyze. `findings` = [(analyzer, score, label)];
    `skipped` = [(analyzer, surface, reason, hint)].
    """
    config = config if config is not None else CONFIG
    registry = registry if registry is not None else REGISTRY
    targets = targets_from_action(action)
    if not targets:
        return None

    on_missing = config.get("on_missing", "suggest")
    an_cfg = config.get("analyzers", {})
    surfaces = sorted({t["surface"] for t in targets})
    findings = []       # (analyzer, score, label)
    skipped = []        # (analyzer, surface, reason, hint)
    satisfied = set()   # surfaces with real coverage

    for t in targets:
        surf = t["surface"]
        ran_any = False
        for name, spec in registry.items():
            if not an_cfg.get(name, {}).get("enabled"):
                continue
            if surf not in spec.get("surfaces", []):
                continue
            if surf == "deps" and spec.get("deps_scope", "any") == "manifest" and not t.get("persisted"):
                continue  # e.g. osv: only audit persisted manifests, not throwaway installs (out of scope)
            if spec.get("builtin"):
                if surf == "bash":
                    sc, fs = builtin_bash(t["command"], t.get("cwd"))
                    satisfied.add("bash")
                elif surf == "python":
                    sc, fs = builtin_python(t.get("content", ""))
                    satisfied.add("python")
                elif surf in ("js", "ts"):
                    sc, fs = builtin_js(t.get("content", ""))
                    satisfied.add(surf)
                elif surf == "secrets":
                    sc, fs, notes = builtin_secrets(t, config)
                    if on_missing != "silent":
                        skipped += [(name, surf, reason, "") for reason in notes]
                    if sc is None:
                        # It ran but could not read the changeset; the ⚪ reason is already
                        # surfaced, and `secrets` stays unsatisfied so nothing masks it.
                        ran_any = True
                        continue
                    satisfied.add("secrets")
                else:  # deps — informational only, does NOT satisfy the vuln check
                    sc, fs = builtin_deps(t)
                src = "%s:%s" % (name, surf)  # e.g. builtin:python — name the rule pack
                for s, lbl in fs:
                    findings.append((src, s, lbl))
                ran_any = True
                continue
            handler = spec.get("handler")
            if handler == "guarddog":
                status = run_guarddog(spec, t)
            elif handler == "gitleaks":
                status = run_gitleaks(spec, t, config)
            else:
                status = run_external(name, spec, t)
            if status[0] == "ok":
                for s, lbl in status[2]:
                    findings.append((name, s, lbl))
                ran_any = True
                satisfied.add(surf)
            elif on_missing != "silent":
                skipped.append((name, surf, status[1], status[2]))
        if not ran_any:
            skipped.append(("(any)", surf, "no analyzer available", ""))

    # Fail-loud: a specific analyzer that was expected but could not run (e.g. osv on an
    # unpinned manifest) is ALWAYS surfaced — another analyzer covering the same surface
    # (guarddog checks malware, not CVEs) must not mask it, or an unchecked CVE surface
    # reads as green. Only the generic "no analyzer at all" note is suppressed once the
    # surface has some coverage.
    skipped = [s for s in skipped if s[0] != "(any)" or s[1] not in satisfied]

    scores = [s for _, s, _ in findings]
    overall = max(scores) if scores else 0
    state = state_of(overall) if findings else NOT_ANALYZED
    return {"surfaces": surfaces, "findings": findings, "skipped": skipped,
            "overall": overall, "state": state}


# ── generic renderers (an adapter maps these onto its runtime's channels) ─────
def render_banner(report):
    """Human-facing one-banner summary."""
    _, glyph, word = report["state"]
    overall, surfaces = report["overall"], report["surfaces"]
    lines = ["%s %d/10 %s — riskscan [%s]" % (glyph, overall, word, ", ".join(surfaces))]
    # The policy line can outscore a real credential, which would put the bullet you most need
    # to read underneath it. Rank actual findings first, then by score.
    for name, s, lbl in sorted(report["findings"],
                               key=lambda x: (x[2].startswith(POLICY_LABEL[:28]), -x[1])):
        if overall > 2 and lbl.startswith(("no known-dangerous", "no credential pattern", "no findings")):
            continue  # drop "nothing found" filler once a real finding exists
        lines.append("  • [%s] %s [%d/10]" % (name, lbl, s))
    for name, surf, reason, hint in report["skipped"]:
        tail = " → %s" % hint if hint else ""
        lines.append("  ⚪ [%s] %s not analyzed — %s%s" % (name, surf, reason, tail))
    return "\n".join(lines)


def render_agent_context(report):
    """Agent-facing advisory: the same analysis, phrased for the model to reconsider."""
    overall, word = report["overall"], report["state"][2]
    bits = ["riskscan advisory (non-blocking) for the action you are about to take: overall %d/10 %s." % (overall, word)]
    if report["findings"]:
        bits.append("Flags: " + "; ".join("%s=%s[%d]" % (n, l, s) for n, s, l in report["findings"]) + ".")
    if report["skipped"]:
        bits.append("Not analyzed: " + "; ".join("%s(%s)" % (n, r) for n, _, r, _ in report["skipped"]) + ".")
    bits.append("If this is more destructive than the task requires, reconsider or confirm with the user before proceeding.")
    return " ".join(bits)
