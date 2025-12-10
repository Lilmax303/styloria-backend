# core/consumers.py

import json
from channels.generic.websocket import AsyncWebsocketConsumer

class NotificationConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        try:
            print("CONNECT STARTED")

            self.user_id = self.scope['url_route']['kwargs']['user_id']
            print("USER ID:", self.user_id)

            self.room_group_name = f'notifications_{self.user_id}'
            print("GROUP:", self.room_group_name)

            # Join the notification group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            print("GROUP ADD SUCCESS")

            await self.accept()
            print("WEBSOCKET ACCEPTED")

            # Send connection confirmation
            await self.send(text_data=json.dumps({
                'message': f'Connected to WebSocket for user {self.user_id}'
            }))
            print("CONNECTION MESSAGE SENT")

        except Exception as e:
            print("ERROR IN CONNECT:", e)

    async def disconnect(self, close_code):
        try:
            # Leave the notification group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
            print("WEBSOCKET DISCONNECTED")
        except Exception as e:
            print("ERROR IN DISCONNECT:", e)

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message = data.get('message', '')

            # Echo the message back
            await self.send(text_data=json.dumps({
                'message': message
            }))
            print("MESSAGE RECEIVED AND SENT BACK:", message)

        except Exception as e:
            print("ERROR IN RECEIVE:", e)

    async def send_notification(self, event):
        try:
            message = event['message']

            await self.send(text_data=json.dumps({
                'message': message
            }))
            print("NOTIFICATION SENT:", message)

        except Exception as e:
            print("ERROR IN send_notification:", e)