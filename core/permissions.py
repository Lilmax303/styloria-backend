# core/permissions.py

from rest_framework import permissions

class IsAuthenticatedAndUser(permissions.BasePermission):
    """Allow access only to authenticated users with the role 'user'."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'user')

class IsAuthenticatedAndProvider(permissions.BasePermission):
    """Allow access only to authenticated users with the role 'provider'."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'provider')

class IsAuthenticatedAndAdmin(permissions.BasePermission):
    """Allow access only to authenticated users with the role 'admin'."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and request.user.role == 'admin')

class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    Assumes the model instance has a `user` attribute.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request (GET, HEAD, OPTIONS)
        if request.method in permissions.SAFE_METHODS:
            return True
        # Write permissions are only allowed to the owner of the object
        return obj.user == request.user