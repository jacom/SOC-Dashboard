from rest_framework.permissions import BasePermission
from .models import MISApiKey


class HasMISApiKey(BasePermission):
    """Allow access only to requests with a valid MIS API Key."""

    message = 'Valid API key required. Set header: X-Api-Key: <key>'

    def has_permission(self, request, view):
        return isinstance(request.auth, MISApiKey)
