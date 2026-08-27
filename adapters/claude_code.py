#!/usr/bin/env python3
"""Claude Code PreToolUse adapter for riskscan.

Default (hook) mode: reads a Claude Code hook payload on stdin, maps the proposed
Bash / Write / Edit / MultiEdit tool call onto a runtime-neutral engine action, and
emits the Claude Code hook response: one traffic-light banner to the user
(``systemMessage``) plus the analysis to the model (``hookSpecificOutput.additionalContext``).
Above the configured danger threshold it sets ``permissionDecision: "ask"`` so the banner
surfaces at approval time. It never blocks; exit is always 0.

CLI modes (to try it without wiring a hook):
  --command "<cmd>"   score a shell command and print the banner
  --file <path>       score a file's contents and print the banner
  --doctor            list analyzers and which ones are installed
  --help              this text
"""
import json
import os
import shutil
import sys

# Run as a bundled script (no install): make the sibling `riskscan` package importable.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from riskscan import engine  # noqa: E402

HELP = """riskscan — advisory risk gate for AI coding agents.

Hook mode (default): reads a Claude Code PreToolUse payload on stdin.

Try it from the CLI:
  {p} --command "rm -rf /tmp/x"      score a shell command
  {p} --file path/to/script.py       score a file's contents
  {p} --doctor                       list analyzers + what's installed
"""


def action_from_payload(payload):
    """Map a Claude Code hook payload to an engine action, or None to opt out."""
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input", {}) or {}
    if tool == "Bash":
        return engine.make_action("command", command=ti.get("command", "") or "")
    if tool in ("Write", "Edit"):
        return engine.make_action(
            "write",
            file_path=ti.get("file_path", "") or "",
            content=ti.get("content") or ti.get("new_string") or "",
        )
    if tool == "MultiEdit":
        edits = ti.get("edits") or []
        content = "\n".join((ed.get("new_string") or "") for ed in edits)
        return engine.make_action("write", file_path=ti.get("file_path", "") or "", content=content)
    return None


def run_hook():
    """Default mode: consume the PreToolUse payload on stdin, emit the hook response."""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    action = action_from_payload(payload)
    if action is None:
        return 0

    config = engine.CONFIG
    report = engine.analyze(action, config)
    if report is None:
        return 0

    color = report["state"][0]
    if config.get("quiet_safe", False) and color == "green" and not report["skipped"]:
        return 0  # nothing worth interrupting for

    banner = engine.render_banner(report)
    context = engine.render_agent_context(report)

    hook_out = {"hookEventName": "PreToolUse", "additionalContext": context}
    # Above the danger threshold, force the permission prompt and attach the banner as its
    # reason (the channel most likely to surface text at approval time). Not a block — the
    # user/model still decide. Below threshold: silent pass, context to the model only.
    ask_threshold = config.get("ask_threshold", 7)
    if report["findings"] and report["overall"] >= ask_threshold:
        hook_out["permissionDecision"] = "ask"
        hook_out["permissionDecisionReason"] = banner

    sys.stdout.write(json.dumps({"systemMessage": banner, "hookSpecificOutput": hook_out}))
    _log(report)
    return 0


def _try(action):
    """CLI: analyze one action and print the banner (no config gating — always show it)."""
    report = engine.analyze(action, engine.CONFIG)
    if report is None:
        print("riskscan: nothing to analyze for that input.")
        return 0
    print(engine.render_banner(report))
    return 0


def _cli(args):
    if "--command" in args:
        i = args.index("--command")
        cmd = args[i + 1] if i + 1 < len(args) else ""
        return _try(engine.make_action("command", command=cmd or ""))
    i = args.index("--file")
    path = args[i + 1] if i + 1 < len(args) else ""
    try:
        with open(path) as f:
            content = f.read()
    except Exception as e:
        print("riskscan: cannot read %s (%s)" % (path, e))
        return 1
    return _try(engine.make_action("write", file_path=path, content=content))


def _doctor():
    """CLI: report each analyzer's enabled state and whether its binary is on PATH."""
    an = engine.CONFIG.get("analyzers", {})
    print("riskscan doctor — analyzer availability\n")
    for name, spec in engine.REGISTRY.items():
        enabled = "on " if an.get(name, {}).get("enabled", False) else "off"
        surfaces = ",".join(spec.get("surfaces", []))
        if spec.get("builtin"):
            print("  [%s] %-12s %-24s (%s)" % (enabled, name, "built-in (always on)", surfaces))
            continue
        found = shutil.which(spec.get("detect", name))
        status = "found" if found else "MISSING"
        hint = "" if found else "   → install: " + (engine._install_hint(spec) or "?")
        print("  [%s] %-12s %-24s (%s)%s" % (enabled, name, status, surfaces, hint))
    print("\n  on/off = config.json (copy config.default.json).  MISSING = enabled but its binary")
    print("  isn't on PATH, so that surface shows ⚪ NOT ANALYZED at runtime.")
    return 0


def _log(report):
    try:
        import datetime
        # CLAUDE_PLUGIN_DATA is a writable, persistent per-plugin dir; fall back to alongside this file.
        logdir = os.environ.get("CLAUDE_PLUGIN_DATA") or os.path.dirname(os.path.abspath(__file__))
        line = "%s  %d/10 %-12s %s\n" % (
            datetime.datetime.now().strftime("%H:%M:%S"),
            report["overall"], report["state"][2], ",".join(report["surfaces"]))
        with open(os.path.join(logdir, "riskscan.log"), "a") as f:
            f.write(line)
    except Exception:
        pass


def main():
    args = sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(HELP.format(p="claude_code.py"))
        return 0
    if "--doctor" in args:
        return _doctor()
    if "--command" in args or "--file" in args:
        return _cli(args)
    return run_hook()


if __name__ == "__main__":
    sys.exit(main())
