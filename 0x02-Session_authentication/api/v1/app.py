#!/usr/bin/env python3
"""
Entry module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

auth = None
auth = os.environ.get('AUTH_TYPE')
if auth == 'auth':
    from api.v1.auth.auth import Auth
    auth = Auth()
elif auth == 'basic_auth':
    from api.v1.auth.basic_auth import BasicAuth
    auth = BasicAuth()
elif auth == 'session_auth':
    from api.v1.auth.session_auth import SessionAuth
    auth = SessionAuth()
elif auth == 'session_exp_auth':
    from api.v1.auth.session_exp_auth import SessionExpAuth
    auth = SessionExpAuth()
elif auth == 'session_db_auth':
    from api.v1.auth.session_db_auth import SessionDBAuth
    auth = SessionDBAuth()


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """Unauthorized handler"""
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """Forbidden handler"""
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def auth_req():
    """check authorization for each request"""
    if not auth:
        return
    path = request.path
    exclud = ['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/',
              '/api/v1/auth_session/login/']
    auth_ = auth.require_auth(path, exclud)
    if not auth_:
        return
    auth_val = auth.authorization_header(request)
    cookie = auth.session_cookie(request)
    if not auth_val and not cookie:
        abort(401)
    current_user = auth.current_user(request)
    if not current_user:
        abort(403)
    request.current_user = current_user


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)
