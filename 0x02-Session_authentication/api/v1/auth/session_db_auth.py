#!/usr/bin/env python3
"""ALX SE Session DB Auth module"""
from api.v1.auth.session_exp_auth import SessionExpAuth
from typing import Union
import uuid
from datetime import datetime, timedelta
from models.user_session import UserSession
from models.base import DATA


class SessionDBAuth(SessionExpAuth):
    """Session auth with DB integration and expiration"""

    def create_session(self, user_id=None) -> Union[str, None]:
        """create a new session"""
        if not user_id:
            return None
        session_id = str(uuid.uuid4())
        if not session_id:
            return None
        session = UserSession(user_id=user_id, session_id=session_id)
        session.save()
        return session_id

    def user_id_for_session_id(self, session_id=None) -> Union[str, None]:
        """Returns a user_id based on the session ID"""
        if not session_id:
            return None
        if 'UserSession' not in DATA:
            return None
        session = UserSession.search({'session_id': session_id})
        if not session:
            return None
        session = session[0]
        if self.session_duration <= 0:
            return session.user_id

        created_at = session.created_at
        duration = timedelta(seconds=self.session_duration)
        if (created_at + duration) < datetime.now():
            return None
        return session.user_id

    def destroy_session(self, request=None) -> bool:
        """Delete current user session"""
        if not request:
            return False
        session_id = self.session_cookies(request)
        if not session_id:
            return False
        if 'UserSession' not in DATA:
            return False
        session = UserSession.search({'session_id': session_id})
        if not session:
            return False
        session = session[0]
        session.remove()
        return True
