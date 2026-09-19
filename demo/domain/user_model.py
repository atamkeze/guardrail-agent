"""User domain model - should have ZERO external architectural dependencies.

This file lives in the 'domain' layer. According to Clean Architecture / DDD,
domain entities must never import from infrastructure, presentation, or application layers.
An AI coding agent added these violations when asked to 'add database persistence'.
"""

# VIOLATION: Domain layer importing from infrastructure layer
from app.infrastructure.database import DatabaseSession, get_engine
from app.infrastructure.repositories.user_repo import UserRepository

# VIOLATION: Domain layer importing from presentation layer
from app.presentation.api.serializers import UserSerializer

# VIOLATION: Domain layer importing from application layer
from app.services.auth_service import validate_token


class User:
    """Core domain entity representing a user."""

    def __init__(self, user_id: int, username: str, email: str):
        self.user_id = user_id
        self.username = username
        self.email = email
        self._repo = UserRepository()  # AI agent directly coupled domain to infra

    def save(self):
        """AI agent added raw database access directly in the domain model."""
        session = DatabaseSession()
        session.add(self)
        session.commit()

    def to_api_response(self):
        """AI agent added presentation logic inside the domain model."""
        return UserSerializer(self).serialize()
