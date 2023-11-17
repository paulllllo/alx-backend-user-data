#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from user import Base, User
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound


class DB:
    """DB class
    """
    params = ['id', 'email', 'session_id', 'reset_token']

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Save the user to the database"""
        user = User(email=email, hashed_password=hashed_password)
        session = self._session
        session.add(user)
        session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        """Find a user in the DB using input arguments"""
        session = self._session
        try:
            user = session.query(User).filter_by(**kwargs).one()
            return user
        except (NoResultFound, InvalidRequestError):
            raise

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates a user in the DB"""
        user = self.find_user_by(id=user_id)
        columns = User.__table__.columns.keys()
        for key, value in kwargs.items():
            if key not in columns:
                raise ValueError
            setattr(user, key, value)
        self._session.add(user)
        self._session.commit()
