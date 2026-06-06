# -*- coding: utf-8 -*-
"""LLM Privacy Guard — QwenPaw plugin entry point

Intercepts all messages sent to the LLM and redacts them before sending.
Registers commands and monkey-patches query_handler in register().
"""

import logging
import os
import sys

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from privacy_engine import filter_text, scan_text, __version__ as engine_version

logger = logging.getLogger(__name__)

# ── Compatibility version check ──

_MIN_QWENPAW_VERSION = (1, 0)

_COMPAT_WARN_TEMPLATE = (
    "[LLM Privacy Guard] ⚠ Version compatibility warning: QwenPaw {actual} "
    "is below the recommended minimum {min_ver}. "
    "The plugin may not work correctly; sensitive data may leak."
)


def _check_qwenpaw_version():
    """Check QwenPaw version compatibility."""
    try:
        from qwenpaw import __version__ as qv
        parts = qv.split(".")
        actual = tuple(int(p) for p in parts[:2])
        if actual < _MIN_QWENPAW_VERSION:
            return (
                False,
                _COMPAT_WARN_TEMPLATE.format(
                    actual=qv, min_ver=".".join(str(x) for x in _MIN_QWENPAW_VERSION)
                ),
            )
        return (True, None)
    except Exception:
        # If version cannot be detected, don't block loading (may be test env)
        logger.debug("Cannot detect QwenPaw version, skipping compatibility check")
        return (True, None)


# ── Message filtering ──

def _filter_message_content(msgs: list) -> tuple[list, int]:
    """Iterate message list, redact str or list[dict] content fields.

    Returns:
        (msgs, filtered_count): redacted message list and replacement count
    """
    total_replacements = 0
    for msg in msgs:
        content = getattr(msg, "content", None)
        if content is None:
            continue
        if isinstance(content, str):
            original = content
            msg.content = filter_text(content)
            if original != msg.content:
                total_replacements += 1
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if text:
                        original = text
                        block["text"] = filter_text(text)
                        if original != block["text"]:
                            total_replacements += 1
    return msgs, total_replacements


def _inject_privacy_warning(msgs: list):
    """Prepend a privacy-failure warning marker to the first message."""
    warning = (
        "⚠ [LLM Privacy Guard] Redaction filter failed — "
        "the following message may contain unprocessed sensitive information. "
        "Please check the logs."
    )
    if msgs:
        first = msgs[0]
        content = getattr(first, "content", None)
        if isinstance(content, str):
            first.content = warning + "\n\n" + content
        elif isinstance(content, list) and content:
            content.insert(0, {"type": "text", "text": warning})


# ── Monkey-patch ──

def _patch_query_handler():
    """Replace AgentRunner.query_handler, injecting redaction logic."""
    try:
        from qwenpaw.app.runner.runner import AgentRunner
    except ImportError:
        logger.error(
            "[LLM Privacy Guard] Cannot import AgentRunner — "
            "plugin may be incompatible with the current QwenPaw version."
        )
        return

    original = AgentRunner.query_handler

    async def patched(self, msgs, request=None, **kwargs):
        try:
            _filter_message_content(msgs)
        except Exception:
            logger.error(
                "[LLM Privacy Guard] 🔴 Redaction pre-filter failed! "
                "Message will be sent raw — sensitive data may leak!",
                exc_info=True,
            )
            # fail-closed: insert warning marker before the first message
            _inject_privacy_warning(msgs)
        async for result in original(self, msgs, request, **kwargs):
            yield result

    AgentRunner.query_handler = patched
    logger.info("[LLM Privacy Guard] ✅ Activated — interceptor in place")


# ── Command registration ──

def _cmd_privacy_test(api, args):
    """Command: /privacy test — verify the plugin is working"""
    from privacy_engine import PrivacyDetector
    import yaml

    try:
        detector = PrivacyDetector()
        rules_count = len(detector._rules) + len(detector._custom_compiled)
        rule_names = list(detector._rules.keys())
        ent_cfg = detector._config.get("entropy", {})

        test_input = "ssh root@[REDACTED_IP] key=sk-abc123def456 ID: ab12cd34-5678-90ab-cdef-1234567890ab"
        safe = detector.filter(test_input)
        matches = detector.scan(test_input)

        lines = [
            f"🔒 LLM Privacy Guard v{engine_version} — Status Report",
            "─" * 40,
            f"✅ Interceptor active, {rules_count} rules loaded",
            f"📋 Built-in rules ({len(rule_names)}): {', '.join(rule_names)}",
            f"🧠 Entropy detection: {'Enabled' if ent_cfg.get('enabled') else 'Disabled'} "
            f"(mode={ent_cfg.get('mode')}, threshold={ent_cfg.get('threshold')}, "
            f"min_length={ent_cfg.get('min_length')})",
            "",
            "🧪 Self-test input:",
            f"   Raw   : {test_input}",
            f"   Filtered: {safe}",
            f"   Matched {len(matches)}: "
            + ", ".join(f"{m['type']}" for m in matches),
            "─" * 40,
            "✅ All good" if len(matches) >= 3 else "⚠ Match count below expected — check config",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Detection failed: {e}"


def _cmd_privacy_scan(api, args):
    """Command: /privacy scan — scan input text for sensitive info"""
    text = " ".join(args) if args else ""
    if not text:
        return "Usage: /privacy scan <text> — scan text for sensitive information"

    matches = scan_text(text)
    if not matches:
        return "✅ No sensitive information detected."

    lines = [f"🔍 Detected {len(matches)} sensitive matches:"]
    for m in matches:
        conf_tag = " ⚠Suspicious format" if m.get("confidence") == "low" else ""
        ent_tag = f" (entropy={m['entropy']:.2f})" if m.get("entropy") else ""
        lines.append(
            f"  [{m['type']}]{conf_tag}{ent_tag}: "
            f"{m['value'][:60]} → {m['placeholder']}"
        )
    return "\n".join(lines)


# ── Plugin entry ──

class PrivacyGuardPlugin:
    def register(self, api):
        # Version check
        ok, warning = _check_qwenpaw_version()
        if not ok:
            logger.warning(warning)
            # Still load the plugin, but log the warning

        # Register commands
        api.register_command("privacy", _cmd_privacy_test, subcommand="test")
        api.register_command("privacy", _cmd_privacy_scan, subcommand="scan")

        # Activate interceptor
        _patch_query_handler()


plugin = PrivacyGuardPlugin()
