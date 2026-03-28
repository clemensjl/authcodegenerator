"""Tests for authcodegenerator."""

import pytest
from authcodegenerator import generate_auth_code


# ---------------------------------------------------------------------------
# Basic output format
# ---------------------------------------------------------------------------


def test_output_format():
    """Code should be WORD-WORD-DIGIT."""
    code = generate_auth_code("secret", "user@example.com")
    parts = code.split("-")
    assert len(parts) == 3, f"Expected 3 parts, got {parts}"
    adj, noun, digit = parts
    assert adj.isupper() and adj.isalpha(), f"Adjective not alpha-upper: {adj!r}"
    assert noun.isupper() and noun.isalpha(), f"Noun not alpha-upper: {noun!r}"
    assert digit.isdigit() and len(digit) == 1, f"Digit part invalid: {digit!r}"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_deterministic_same_inputs():
    """Same (secret, identifier) must always produce the same code."""
    code1 = generate_auth_code("mysecret", "alice")
    code2 = generate_auth_code("mysecret", "alice")
    assert code1 == code2


def test_deterministic_with_counter():
    """Counter is respected deterministically."""
    c0 = generate_auth_code("mysecret", "alice", counter=0)
    c0_again = generate_auth_code("mysecret", "alice", counter=0)
    assert c0 == c0_again


# ---------------------------------------------------------------------------
# Sensitivity to inputs
# ---------------------------------------------------------------------------


def test_different_secrets_produce_different_codes():
    code1 = generate_auth_code("secret-A", "alice")
    code2 = generate_auth_code("secret-B", "alice")
    assert code1 != code2


def test_different_identifiers_produce_different_codes():
    code1 = generate_auth_code("secret", "alice")
    code2 = generate_auth_code("secret", "bob")
    assert code1 != code2


def test_counter_changes_code():
    """Different counter values should (almost always) yield different codes."""
    codes = {generate_auth_code("s", "u", counter=i) for i in range(10)}
    # With 10 distinct counter values the probability of all colliding is
    # negligibly small; we just require at least 2 distinct outputs.
    assert len(codes) >= 2


# ---------------------------------------------------------------------------
# Counter validation
# ---------------------------------------------------------------------------


def test_counter_zero_is_default():
    explicit = generate_auth_code("s", "u", counter=0)
    default = generate_auth_code("s", "u")
    assert explicit == default


def test_counter_large_value():
    """Large counters should work without error."""
    code = generate_auth_code("s", "u", counter=2**32)
    assert len(code.split("-")) == 3


# ---------------------------------------------------------------------------
# Input validation – TypeError
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_secret", [None, 42, b"bytes", 3.14])
def test_secret_type_error(bad_secret):
    with pytest.raises(TypeError):
        generate_auth_code(bad_secret, "id")


@pytest.mark.parametrize("bad_id", [None, 42, b"bytes", []])
def test_identifier_type_error(bad_id):
    with pytest.raises(TypeError):
        generate_auth_code("secret", bad_id)


@pytest.mark.parametrize("bad_counter", [None, "1", 1.5])
def test_counter_type_error(bad_counter):
    with pytest.raises(TypeError):
        generate_auth_code("secret", "id", counter=bad_counter)


# ---------------------------------------------------------------------------
# Input validation – ValueError
# ---------------------------------------------------------------------------


def test_negative_counter_raises():
    with pytest.raises(ValueError):
        generate_auth_code("secret", "id", counter=-1)


# ---------------------------------------------------------------------------
# Edge-case inputs
# ---------------------------------------------------------------------------


def test_empty_secret():
    """Empty secret is allowed; code is still generated."""
    code = generate_auth_code("", "user")
    assert len(code.split("-")) == 3


def test_empty_identifier():
    """Empty identifier is allowed."""
    code = generate_auth_code("secret", "")
    assert len(code.split("-")) == 3


def test_unicode_inputs():
    """Unicode characters in secret/identifier should work."""
    code = generate_auth_code("sécret", "用户@example.com")
    assert len(code.split("-")) == 3


def test_long_inputs():
    code = generate_auth_code("s" * 1000, "i" * 1000)
    assert len(code.split("-")) == 3
