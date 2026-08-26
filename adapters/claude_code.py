#!/usr/bin/env python3
"""Claude Code PreToolUse adapter for riskscan.

Reads a Claude Code hook payload on stdin, maps the proposed Bash / Write / Edit
tool call onto a runtime-neutral engine action, and emits the Claude Code hook
response: one traffic-light banner to the user (``systemMessage``) plus the
analysis to the model (``hookSpecificOutput.additionalContext``). Above the
configured danger threshold it sets ``permissionDecision: "ask"`` so the banner
surfaces at approval time. It never blocks; exit is always 0.
"""
import json
import os
import sys

# Run as a bundled script (no install): make the sibling `riskscan` package importable.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from riskscan import engine  # noqa: E402


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


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    action = action_from_payload(payload)
    if action is None:
        return 0

    config = engine.DEFAULT_CONFIG
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


if __name__ == "__main__":
    sys.exit(main())
