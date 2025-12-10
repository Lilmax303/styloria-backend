"""
ASGI config for styloria_project project.

It exposes the ASGI callable as a module-level variable named `application`.

For more information on this file, see:
https://docs.djangoprojectproject.com/en/6.0/howto/deployment/asgi/
"""

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import core.routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'styloria_project.settings')

# Initialize the Django ASGI application
django_asgi_app = get_asgi_application()

# Define the ASGI application with routing for HTTP and WebSockets
application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': AuthMiddlewareStack(
        URLRouter(
            core.routing.websocket_urlpatterns
        )
    ),
})