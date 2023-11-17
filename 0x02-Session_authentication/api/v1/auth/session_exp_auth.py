#!/usr/bin/env python3
"""ALX SE Session Auth module"""
from api.v1.auth.session_auth import SessionAuth
import os
from typing import Union
from datetime import datetime, timedelta


class SessionExpAuth(SessionAuth):
    """Session auth expiration class"""
    session_dictionary = {}

    def __init__(self):
        """Initialize the class"""
        duration = os.environ.get('SESSION_DURATION')
        try:
            if not duration:
                duration = 0
            duration = int(duration)
        except ValueError:
            duration = 0
        self.session_duration = duration

    def create_session(self, user_id=None) -> Union[str, None]:
        """create new session from super() class"""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        self.session_dictionary['user_id'] = user_id
        self.session_dictionary['created_at'] = datetime.now()
        self.user_id_by_session_id[session_id] = self.session_dictionary
        return session_id

    def user_id_for_session_id(self, session_id=None) -> Union[str, None]:
        """Returns a user_id based on the session ID"""
        if not session_id:
            return None
        if session_id not in self.user_id_by_session_id:
            return None
        if self.session_duration <= 0:
            return self.session_dictionary.get('user_id')
        if 'created_at' not in self.session_dictionary:
            return None
        created_at = self.session_dictionary.get('created_at')
        duration = timedelta(seconds=self.session_duration)
        if (created_at + duration) < datetime.now():
            return None
        return self.session_dictionary.get('user_id')
