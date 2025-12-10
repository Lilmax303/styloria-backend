from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from core.models import Notification

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