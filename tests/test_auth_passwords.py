"""Tests for password hashing and verification in :mod:`src.auth`."""

from __future__ import annotations

from unittest.mock import patch

from src import auth


def test_hash_is_salted_and_not_plaintext() -> None:
    first = auth.hash_password("correct horse battery")
    second = auth.hash_password("correct horse battery")
    assert "correct horse battery" not in first
    assert first != second  # random salt per hash
    assert first.startswith(auth.password_hash_method())


def test_scrypt_used_when_available() -> None:
    # every supported Python build ships hashlib.scrypt via OpenSSL
    assert auth.password_hash_method() == "scrypt"


def test_verify_correct_and_wrong_password() -> None:
    stored = auth.hash_password("correct horse battery")
    assert auth.verify_password(stored, "correct horse battery") is True
    assert auth.verify_password(stored, "correct horse batterY") is False
    assert auth.verify_password(stored, "") is False


def test_verify_against_missing_user_still_hashes() -> None:
    """No user -> always False, but the password is still checked against
    a dummy hash so the response takes comparable time."""
    with patch.object(auth, "check_password_hash", wraps=auth.check_password_hash) as check:
        assert auth.verify_password(None, "whatever-password") is False
    check.assert_called_once()
    assert check.call_args.args[0] == auth._dummy_hash()


def test_dummy_hash_uses_the_same_method() -> None:
    assert auth._dummy_hash().startswith(auth.password_hash_method())


def test_malformed_hash_never_matches() -> None:
    assert auth.verify_password("not-a-real-hash", "anything") is False
