"""Fake database module for Faraday Gate demo."""

CONNECTION_STRING = "postgres://fake_user:fake_password@localhost:5432/fake_db"


def fake_connect():
    """Pretend to connect to a database.

    This does not actually connect to anything.
    """

    return None
