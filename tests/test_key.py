import pytest

from websinaro.webcrypten.core.key import Key
from websinaro.webcrypten.utils.exceptions import SmallKeyError, NotStandardFormError, KeyLoadError

GOOD_KEY = "Xk9pQ2vN8mL4wR7tY1zA6bC3dF5gH0jK+/=="  # 38 chars, valid charset


def test_missing_env_raises_keyloaderror(monkeypatch):
    monkeypatch.delenv("MASTER_KEY", raising=False)
    with pytest.raises(KeyLoadError):
        Key()


def test_manual_key_overrides_env(monkeypatch):
    monkeypatch.setenv("MASTER_KEY", GOOD_KEY)
    other_key = "aB3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY=="
    k = Key(master_key=other_key)
    assert k.master_key == other_key  # manual key wins, env ignored


def test_env_key_used_when_no_manual_key(monkeypatch):
    monkeypatch.setenv("MASTER_KEY", GOOD_KEY)
    k = Key()
    assert k.master_key == GOOD_KEY


def test_short_key_raises_smallkeyerror():
    with pytest.raises(SmallKeyError):
        Key(master_key="short")


def test_bad_charset_raises_notstandardformerror():
    with pytest.raises(NotStandardFormError):
        Key(master_key="a" * 40 + " has spaces and !!invalid##")


def test_non_string_raises_notstandardformerror():
    with pytest.raises(NotStandardFormError):
        Key(master_key=12345678901234567890)


def test_derive_keys_returns_two_distinct_32_byte_keys(monkeypatch):
    monkeypatch.setenv("MASTER_KEY", GOOD_KEY)
    k = Key()
    key1, key2 = k.derive_keys()
    assert len(key1) == 32
    assert len(key2) == 32
    assert key1 != key2


def test_derive_keys_deterministic_for_same_master_key(monkeypatch):
    monkeypatch.setenv("MASTER_KEY", GOOD_KEY)
    k1 = Key()
    k2 = Key()
    assert k1.derive_keys() == k2.derive_keys()  # same input -> same output, always
