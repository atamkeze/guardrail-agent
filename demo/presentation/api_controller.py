"""API Controller in the presentation layer.

This file lives in the 'presentation' layer. According to Clean Architecture,
presentation controllers must NOT directly import raw infrastructure/database drivers.
An AI coding agent violated this by importing SQLAlchemy directly when asked to 'add a user endpoint'.
"""

# VIOLATION: Presentation layer importing directly from infrastructure
from app.infrastructure.database import engine, SessionLocal
from app.database.models import UserTable
from app.repositories.user_repo import UserRepo

import json


class UserAPIController:
    """REST API controller for user management."""

    def __init__(self):
        # AI agent directly coupled presentation to infrastructure
        self.db = SessionLocal()

    def get_user(self, user_id: int):
        """Fetch user - AI bypassed the service/application layer entirely."""
        user = self.db.query(UserTable).filter(UserTable.id == user_id).first()
        return json.dumps({"id": user.id, "name": user.name})

    def list_users(self):
        """List all users with raw database query in controller."""
        users = self.db.query(UserTable).all()
        return json.dumps([{"id": u.id, "name": u.name} for u in users])
