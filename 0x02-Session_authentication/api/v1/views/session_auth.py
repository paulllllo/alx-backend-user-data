#!/usr/bin/env python3
"""Module to handle all routes for session auth"""
from api.v1.views import app_views
from flask import request, jsonify, make_response
from models.user import User
import os
from typing import Union, Dict


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def create_session() -> str:
    """Create a new session when a user logs in"""
    user_email = request.form.get('email')
    if not user_email or not len(user_email):
        return jsonify({"error": "email missing"}), 400

    user_pwd = request.form.get('password')
    if not user_pwd or not len(user_pwd):
        return jsonify({"error": "password missing"}), 400

    users = User.search({'email': user_email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404
    for user in users:
        if user.is_valid_password(user_pwd):
            from api.v1.app import auth
            session_id = auth.create_session(user.id)
            session_name = os.environ.get('SESSION_NAME')
            res = make_response(user.to_json())
            res.set_cookie(session_name, session_id)
            return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def delete_session() -> Union[bool, Dict]:
    """delete user session on logout"""
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
