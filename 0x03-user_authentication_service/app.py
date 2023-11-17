#!/usr/bin/env python3
"""flask app"""
from flask import Flask, jsonify, request, abort, redirect, url_for
from auth import Auth


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=["GET"], strict_slashes=False)
def index():
    """Home page"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_users():
    """Route to register a new user"""
    data = request.form
    email = data.get('email')
    password = data.get('password')

    try:
        new_user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login_user():
    """create a new session when user logs in"""
    data = request.form
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        abort(401)
    user = AUTH.valid_login(email, password)
    if not user:
        abort(401)
    session_id = AUTH.create_session(email)
    response = jsonify({"email": email, "message": "logged in"})
    response.set_cookie("session_id", session_id)
    return response


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout_user():
    """Logout the user"""
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    user_id = user.id
    AUTH.destroy_session(user_id)
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """Return the profile of the user"""
    session_id = request.cookies.get('session_id')
    if not session_id:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    email = user.email
    return jsonify({"email": email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """Get the password reset token for a user with email"""
    email = request.form.get('email')
    if not email:
        abort(403)
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """Update the user password"""
    data = request.form
    email = data.get('email')
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')
    if not (email and reset_token and new_password):
        abort(403)
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
