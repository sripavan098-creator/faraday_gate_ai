"""Fake authentication module for Faraday Gate demo."""

FAKE_USERS = {
    "demo": "demo-password-placeholder",
}


def login(username: str, password: str) -> bool:
    """Fake login function.

    This is intentionally insecure and exists only for demo purposes.
    """

    expected = FAKE_USERS.get(username)

    if expected is None:
        return False

    return password == expected
