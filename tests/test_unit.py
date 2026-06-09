# -*- coding: utf-8 -*-
"""Unit tests for internal helper functions."""

import pytest
from privacy_engine.detector import _luhn_check
from privacy_engine.entropy import _shannon_entropy, _may_be_secret
from privacy_engine.whitelist import (
    is_whitelisted_ip,
    is_whitelisted_domain,
    is_whitelisted_hostname,
)


class TestLuhnCheck:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_valid_amex(self):
        assert _luhn_check("340000000000009") is True

    def test_invalid_card(self):
        assert _luhn_check("4392579912345678") is False

    def test_too_short(self):
        assert _luhn_check("1234") is False

    def test_with_spaces(self):
        assert _luhn_check("4111 1111 1111 1111") is True

    def test_with_hyphens(self):
        assert _luhn_check("4111-1111-1111-1111") is True

    def test_empty(self):
        assert _luhn_check("") is False

    def test_non_digit_chars_ignored(self):
        assert _luhn_check("4111-1111-1111-1111") is True


class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("a") == 0.0

    def test_all_same_char(self):
        assert _shannon_entropy("aaaaaaaa") == 0.0

    def test_english_text_low_entropy(self):
        ent = _shannon_entropy("hello world this is a test")
        assert ent < 5.0

    def test_random_base64_high_entropy(self):
        ent = _shannon_entropy("mW7xK2pQ9vR4nB6fL3jH8cY1")
        assert ent > 4.0


class TestMayBeSecret:
    def test_empty(self):
        assert _may_be_secret("") is False

    def test_single_char_repeated(self):
        assert _may_be_secret("aaaaaaa") is False

    def test_newlines(self):
        assert _may_be_secret("abc\ndef") is False

    def test_tabs(self):
        assert _may_be_secret("abc\tdef") is False

    def test_cjk_text(self):
        assert _may_be_secret("这是一段中文测试文本内容很长") is False

    def test_too_many_spaces(self):
        assert _may_be_secret("a b c d e f g h i j") is False

    def test_likely_token(self):
        assert _may_be_secret("dGhpcyBpcyBhIHRlc3Q") is True

    def test_normal_word(self):
        assert _may_be_secret("configuration") is True


class TestWhitelist:
    def test_whitelisted_ip_zeros(self):
        assert is_whitelisted_ip("0.0.0.0") is True

    def test_whitelisted_ip_broadcast(self):
        assert is_whitelisted_ip("255.255.255.255") is True

    def test_non_whitelisted_ip(self):
        assert is_whitelisted_ip("203.0.113.1") is False

    def test_whitelisted_domain_localhost(self):
        assert is_whitelisted_domain("localhost") is True

    def test_whitelisted_domain_example(self):
        assert is_whitelisted_domain("example.com") is True

    def test_non_whitelisted_domain(self):
        assert is_whitelisted_domain("company.com") is False

    def test_whitelisted_hostname(self):
        assert is_whitelisted_hostname("localhost") is True

    def test_non_whitelisted_hostname(self):
        assert is_whitelisted_hostname("my-server") is False
