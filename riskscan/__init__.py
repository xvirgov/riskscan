"""riskscan — runtime-agnostic risk scoring engine for proposed agent actions.

The engine (``riskscan.engine``) knows nothing about any specific agent runtime.
Runtime integration lives in adapters/ (e.g. adapters/claude_code.py maps a
Claude Code PreToolUse hook payload onto the engine and back).
"""
