"""Local password hashing with Argon2id."""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_ph = PasswordHasher()  # argon2id defaults are sound for interactive logins

# A throwaway hash used only to burn the same Argon2 work when no user record exists.
# Without it, "unknown user" returns before any hashing happens while "known user, wrong
# password" pays the full Argon2id cost — a timing oracle that enumerates valid usernames
# despite the generic error message (CWE-208). Computed once at import.
_DUMMY_HASH = _ph.hash("argon2-timing-equalizer")


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(password_hash: str | None, plaintext: str) -> bool:
    if not password_hash:
        return False
    try:
        return _ph.verify(password_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError, Exception):  # noqa: BLE001
        return False


def burn_password_time(plaintext: str) -> None:
    """Spend the same time a real verification would, then discard the result.

    Call this on the "user not found / inactive" branch of a login so both outcomes take
    comparable wall-clock time.
    """
    verify_password(_DUMMY_HASH, plaintext or "")


def needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except Exception:  # noqa: BLE001
        return False
