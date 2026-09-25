from samples.repo.src.auth import login


def test_login_success():
    assert login("demo", "demo-password-placeholder") is True


def test_login_failure():
    assert login("demo", "wrong-password") is False
