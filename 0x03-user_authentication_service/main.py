#!/usr/bin/env python3
"""End to end testing module."""
import requests

BASE = 'http://127.0.0.1:5000'


def register_user(email: str, password: str) -> None:
    """Test the register_user route."""
    payload = {'email': email, 'password': password}
    res = requests.post(f'{BASE}/users', data=payload)
    expected = {'email': email, 'message': 'user created'}
    assert 200 == res.status_code
    assert expected == res.json()


def log_in_wrong_password(email: str, password: str) -> None:
    """Test login with invalid credential."""
    payload = {'email': email, 'password': password}
    res = requests.post(f'{BASE}/sessions', data=payload)
    assert res.status_code == 401


def profile_unlogged() -> None:
    """Test try getting profile when not logged in."""
    res = requests.get(f'{BASE}/profile')
    assert res.status_code == 403


def log_in(email: str, password: str) -> str:
    """Test login with valid credential."""
    payload = {'email': email, 'password': password}
    res = requests.post(f'{BASE}/sessions', data=payload)
    expected = {'email': email, 'message': 'logged in'}
    assert res.status_code == 200
    assert expected == res.json()
    return res.cookies.get('session_id')


def profile_logged(session_id: str) -> None:
    """Test try getting profile when logged in."""
    cookies = dict(session_id=session_id)
    res = requests.get(f'{BASE}/profile', cookies=cookies)
    output = res.json()
    expected = {'email': output.get('email')}
    assert res.status_code == 200
    assert output == expected


def log_out(session_id: str) -> None:
    """Check logout route."""
    cookies = dict(session_id=session_id)
    res = requests.delete(f'{BASE}/sessions', cookies=cookies)
    assert res.status_code == 200


def reset_password_token(email: str) -> str:
    """Test reset password token."""
    payload = {'email': email}
    res = requests.post(f'{BASE}/reset_password', data=payload)
    output = res.json()
    reset_token = output.get('reset_token')
    expect = {'email': email, 'reset_token': reset_token}

    assert res.status_code == 200
    assert output == expect
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test update password route."""
    payload = {'email': email,
               'reset_token': reset_token, 'new_password': new_password}
    res = requests.put(f'{BASE}/reset_password', data=payload)
    expect = {'email': email, 'message': 'Password updated'}
    assert res.status_code == 200
    assert res.json() == expect


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
