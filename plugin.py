# -*- coding: utf-8 -*-
"""LLM Privacy Guard — QwenPaw 插件入口

拦截所有发往 LLM 的消息，在发送前脱敏。
在 register() 中注册命令并 monkey-patch query_handler。
"""

import logging
import os
import sys

_plugin_dir = os.path.dirname(os.path.abspath(__file__))
if _plugin_dir not in sys.path:
    sys.path.insert(0, _plugin_dir)

from privacy_engine import filter_text, scan_text, __version__ as engine_version

logger = logging.getLogger(__name__)

# ── 兼容性版本检查 ──

_MIN_QWENPAW_VERSION = (1, 0)

_COMPAT_WARN_TEMPLATE = (
    "[LLM Privacy Guard] ⚠ 版本兼容性警告: QwenPaw {actual} 低于建议的最低版本 {min_ver}。"
    "插件可能无法正常工作，敏感数据可能未被过滤。"
)


def _check_qwenpaw_version():
    """检查 QwenPaw 版本兼容性。"""
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
        # 无法检测版本时不阻止加载（可能是在测试环境）
        logger.debug("无法检测 QwenPaw 版本，跳过兼容性检查")
        return (True, None)


# ── 消息过滤 ──

def _filter_message_content(msgs: list) -> tuple[list, int]:
    """遍历消息列表，对 str 或 list[dict] 类型的 content 脱敏。

    Returns:
        (msgs, filtered_count): 脱敏后的消息列表和替换次数
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
    """在消息前插入隐私保护失败的警告标记。"""
    warning = (
        "⚠ [LLM Privacy Guard] 脱敏过滤器异常，以下消息可能包含未处理的敏感信息。"
        "请检查日志。"
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
    """替换 AgentRunner.query_handler，注入脱敏逻辑。"""
    try:
        from qwenpaw.app.runner.runner import AgentRunner
    except ImportError:
        logger.error(
            "[LLM Privacy Guard] 无法导入 AgentRunner，"
            "插件在当前 QwenPaw 版本中可能不兼容。"
        )
        return

    original = AgentRunner.query_handler

    async def patched(self, msgs, request=None, **kwargs):
        try:
            _filter_message_content(msgs)
        except Exception:
            logger.error(
                "[LLM Privacy Guard] 🔴 脱敏预处理失败！"
                "消息将以原始内容发送，敏感数据可能泄露！",
                exc_info=True,
            )
            # fail-closed: 在第一条消息前插入警告标记
            _inject_privacy_warning(msgs)
        async for result in original(self, msgs, request, **kwargs):
            yield result

    AgentRunner.query_handler = patched
    logger.info("[LLM Privacy Guard] ✅ 已激活，拦截器就位")


# ── 命令注册 ──

def _cmd_privacy_test(api, args):
    """命令: /privacy test — 验证插件是否正常工作"""
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
            f"🔒 LLM Privacy Guard v{engine_version} — 状态报告",
            "─" * 40,
            f"✅ 拦截器激活，{rules_count} 条规则就绪",
            f"📋 内置规则 ({len(rule_names)}): {', '.join(rule_names)}",
            f"🧠 熵检测: {'启用' if ent_cfg.get('enabled') else '关闭'} "
            f"(模式={ent_cfg.get('mode')}, 阈值={ent_cfg.get('threshold')}, "
            f"最小长度={ent_cfg.get('min_length')})",
            "",
            "🧪 自测输入:",
            f"   原始: {test_input}",
            f"   过滤: {safe}",
            f"   匹配 {len(matches)} 处: "
            + ", ".join(f"{m['type']}" for m in matches),
            "─" * 40,
            "✅ 一切正常" if len(matches) >= 3 else "⚠ 匹配数少于预期，请检查配置",
        ]
        return "\n".join(lines)
    except Exception as e:
        return f"❌ 检测失败: {e}"


def _cmd_privacy_scan(api, args):
    """命令: /privacy scan — 扫描当前输入中的敏感信息"""
    text = " ".join(args) if args else ""
    if not text:
        return "用法: /privacy scan <文本>  — 扫描文本中的敏感信息"

    matches = scan_text(text)
    if not matches:
        return "✅ 未检测到敏感信息。"

    lines = [f"🔍 检测到 {len(matches)} 处敏感信息:"]
    for m in matches:
        conf_tag = " ⚠格式可疑" if m.get("confidence") == "low" else ""
        ent_tag = f" (熵={m['entropy']:.2f})" if m.get("entropy") else ""
        lines.append(
            f"  [{m['type']}]{conf_tag}{ent_tag}: "
            f"{m['value'][:60]} → {m['placeholder']}"
        )
    return "\n".join(lines)


# ── 插件入口 ──

class PrivacyGuardPlugin:
    def register(self, api):
        # 版本检查
        ok, warning = _check_qwenpaw_version()
        if not ok:
            logger.warning(warning)
            # 仍然加载插件，但记录警告

        # 注册命令
        api.register_command("privacy", _cmd_privacy_test, subcommand="test")
        api.register_command("privacy", _cmd_privacy_scan, subcommand="scan")

        # 激活拦截器
        _patch_query_handler()


plugin = PrivacyGuardPlugin()
