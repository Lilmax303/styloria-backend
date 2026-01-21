# core/utils.py

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from core.models import Notification
from django.utils import timezone
from decimal import Decimal
from django.db.models import Count


def send_user_notification(user_id, message):
    print("UTILS: Starting send_user_notification")
    print("UTILS: user_id =", user_id)
    print("UTILS: message =", message)

    # Save notification to database
    Notification.objects.create(
        user_id=user_id,
        message=message,
    )
    print("UTILS: Notification saved to database")

    # Send to WebSocket
    layer = get_channel_layer()
    print("UTILS: channel layer =", layer)

    group = f"notifications_{user_id}"
    print("UTILS: group =", group)

    async_to_sync(layer.group_send)(
        group,
        {
            "type": "send_notification",
            "message": message,
        }
    )

    print("UTILS: Message sent to group")

def send_websocket_notification(user, message, notification_type='info'):
    """
    Send real-time notification via WebSocket.
    """
    from .models import Notification
    
    # Save to database
    Notification.objects.create(
        user=user,
        message=message,
        read=False,
        timestamp=timezone.now()
    )
    
    # Send via WebSocket
    channel_layer = get_channel_layer()
    user_room_group = f'notifications_{user.id}'
    
    try:
        async_to_sync(channel_layer.group_send)(
            user_room_group,
            {
                'type': 'send_notification',
                'message': {
                    'type': notification_type,
                    'text': message,
                    'timestamp': timezone.now().isoformat()
                }
            }
        )
    except Exception:
        pass  # WebSocket might not be connected, that's okay

