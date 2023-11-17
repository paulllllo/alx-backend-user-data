#!/usr/bin/env python3
"""ALX SE Backend custom session authentication module"""
from api.v1.auth.auth import Auth
import uuid
from typing import Dict, Any, Union
from flask import request
from models.user import User


class SessionAuth(Auth):
    """Session auth class to manage the session auth service"""
    user_id_by_session_id: Dict[str, Any] = {}

    def create_session(self, user_id: str = None) -> Union[str, None]:
        """Creates a session ID for a user with user_id"""
        if not user_id or type(user_id) is not str:
            return None
        session_id: str = str(uuid.uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(
            self, session_id: str = None) -> Union[str, None]:
        """Returns a User ID based on a Session ID"""
        if not session_id or type(session_id) is not str:
            return None
        user_id: str = self.user_id_by_session_id.get(session_id)
        return user_id

    def current_user(self, request=None) -> Union[User, None]:
        """Returns the current user from db using its id from the cookie"""
        # get the cookie value which is the sesison ID
        session_id = self.session_cookie(request)
        if not session_id:
            return None
        # Use the session ID to get the User ID
        user_id = self.user_id_for_session_id(session_id)
        if not user_id:
            return None
        # Use user ID to get the user
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None) -> bool:
        """Destroy user session on logout"""
        if not request:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        if not self.user_id_for_session_id(session_id):
            return False
        del self.user_id_by_session_id[session_id]
        return True
