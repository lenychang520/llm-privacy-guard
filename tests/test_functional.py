# -*- coding: utf-8 -*-
"""Functional tests — positive detection, adversarial regression, known limitations."""

import pytest
from privacy_engine import filter_text, scan_text, add_rule, PrivacyDetector


@pytest.fixture(autouse=True)
def reset_detector():
    """Reset detector before each test to avoid custom rule leakage."""
    from privacy_engine import reload_config
    reload_config()


# ══════════════════════════════════════════════════════
# Positive functional tests
# ══════════════════════════════════════════════════════

def test_ipv4_public():
    result = filter_text("ssh root@203.0.113.1 ufw status")
    assert "[IP]" in result
    assert "203.0.113.1" not in result


def test_uuid_with_hyphens():
    result = filter_text("UUID: 4e0a1c0d-3342-4d5b-8785-6618aff9b102")
    assert "[UUID]" in result
    assert "4e0a1c0d" not in result


def test_api_key():
    result = filter_text("Authorization: Bearer sk-abc123def45678901234567890")
    assert "[API_KEY]" in result
    assert "sk-abc123" not in result


def test_private_ips_filtered():
    result = filter_text("ping 127.0.0.1 && ping 192.168.1.1 && ping 10.0.0.1")
    assert all(x not in result for x in ["127.0.0.1", "192.168.1.1", "10.0.0.1"])


def test_protocol_address_whitelisted():
    result = filter_text("bind 0.0.0.0:8080")
    assert "0.0.0.0" in result


def test_scan_detection():
    matches = scan_text(
        "IP: 203.0.113.1, UUID: abcd1234-5678-abcd-1234-5678abcdef01, "
        "key=sk-test12345678901234567890"
    )
    assert len(matches) >= 3


def test_custom_rule():
    add_rule("test_project", r"PROJ-\d{6}", "[PROJECT]")
    result = filter_text("deploy PROJ-123456 to server")
    assert "[PROJECT]" in result


def test_email():
    result = filter_text("contact admin@company.com")
    assert "[EMAIL]" in result


def test_phone_cn():
    result = filter_text("phone: 13812345678")
    assert "[PHONE]" in result


def test_id_card_cn():
    result = filter_text("ID: 110101199001011234")
    assert "[ID_CARD]" in result


def test_rules_loaded():
    d = PrivacyDetector()
    assert len(d._rules) >= 18


# ══════════════════════════════════════════════════════
# Adversarial regression tests (should be fixed)
# ══════════════════════════════════════════════════════

def test_fullwidth_digits_to_phone():
    result = filter_text("电话: １３９１２３４５６７８")
    assert "[PHONE]" in result


def test_fullwidth_digits_card_no_replace():
    result = filter_text("卡号 ４３９２ ５７９９ １２３４ ５６７８")
    assert "[CARD]" not in result


def test_fullwidth_digits_card_scan():
    m = scan_text("卡号 ４３９２ ５７９９ １２３４ ５６７８")
    assert any(
        x["type"] == "credit_card" and x["confidence"] == "low" for x in m
    )


def test_aws_key_lowercase():
    result = filter_text("register akiaqt4v25abcd6efghj test")
    assert "[AWS_KEY]" in result


def test_github_pat_new_prefix():
    result = filter_text(
        "token is github_pat_11A22B33C44D55E66F77G88H99I00J11K22L33"
    )
    assert "[GITHUB_TOKEN]" in result


def test_ssh_pkcs8_generic():
    result = filter_text(
        "-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----"
    )
    assert "[SSH_KEY]" in result
    # Verify the entire key block is replaced — no base64 leak
    assert "MIIEvg" not in result
    assert "BEGIN PRIVATE KEY" not in result
    assert "END PRIVATE KEY" not in result


def test_uuid_no_hyphens():
    result = filter_text("trace id: 550e8400e29b41d4a716446655440000")
    assert "[UUID]" in result


def test_db_connection_dialect():
    result = filter_text(
        "connect postgresql+psycopg2://admin:pass@db.example.com:5432/prod"
    )
    assert "[DB_URL]" in result


def test_db_cli():
    result = filter_text(
        "psql -h pg-server.internal -U readonly -d prod -p 5432"
    )
    assert "[DB_CMD]" in result


def test_credit_card_luhn_fail_no_replace():
    result = filter_text("card 4392 5799 1234 5678")
    assert "[CARD]" not in result


def test_credit_card_luhn_fail_scan():
    m = scan_text("card 4392 5799 1234 5678")
    assert any(x["type"] == "credit_card" for x in m)


def test_ipv6_hyphen():
    result = filter_text(
        "connect FE80-0000-0000-0000-0202-B3FF-FE1E-8329 failed"
    )
    assert "[IP]" in result


def test_ipv6_brackets_no_debris():
    result = filter_text("endpoint [2001:db8::1] port 443 timeout")
    assert "[IP]" in result
    assert "1]" not in result


def test_ipv6_mixed_ipv4():
    result = filter_text("address ::ffff:192.0.2.1 format")
    assert "[IP]" in result
    assert "0.2.1" not in result


def test_ipv4_hex():
    result = filter_text("address 0xC0A80101 maps to")
    assert "[IP]" in result


def test_jwt_multiline():
    result = filter_text(
        "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
        ".\neyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\n"
        ".\nsignature"
    )
    assert "[JWT]" in result


def test_phone_parentheses():
    result = filter_text("phone (138) 1234-5678")
    assert "[PHONE]" in result


def test_id_card_hyphens():
    result = filter_text("ID 110101-19900101-1234 verify")
    assert "[ID_CARD]" in result


# ══════════════════════════════════════════════════════
# Known limitations (expected leaks)
# ══════════════════════════════════════════════════════

@pytest.mark.xfail(reason="Known limitation: [.] bypass not handled")
def test_bracket_dot_bypass():
    result = filter_text("address 192[.]168[.]1[.]150 check")
    assert "192[.]168[.]1[.]150" not in result


def test_at_bypass_expected_leak():
    result = filter_text("email zhangjie at company")
    assert "zhangjie at company" in result


def test_ip_spaces_expected_leak():
    result = filter_text("address 192. 168. 1. 1 check")
    assert "192. 168. 1. 1" in result
