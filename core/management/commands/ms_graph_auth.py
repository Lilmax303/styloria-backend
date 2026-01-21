# core/management/commands/ms_graph_auth.py



import msal
from django.conf import settings
from django.core.management.base import BaseCommand
from core.utils.ms_graph_mail import _load_cache, _save_cache


class Command(BaseCommand):
    help = "Authenticate a Microsoft account (device code flow) and cache token for Graph sendMail."

    def handle(self, *args, **options):
        client_id = getattr(settings, "MS_GRAPH_CLIENT_ID", "")
        authority = getattr(settings, "MS_GRAPH_AUTHORITY", "https://login.microsoftonline.com/consumers")
        scopes = getattr(settings, "MS_GRAPH_SCOPES", ["User.Read", "Mail.Send", "offline_access"])

        if not client_id:
            self.stderr.write("MS_GRAPH_CLIENT_ID is not set.")
            return

        cache = _load_cache()

        app = msal.PublicClientApplication(
            client_id=client_id,
            authority=authority,
            token_cache=cache,
        )

        flow = app.initiate_device_flow(scopes=scopes)
        if "user_code" not in flow:
            raise RuntimeError(f"Failed to start device flow: {flow}")

        self.stdout.write(flow["message"])
        result = app.acquire_token_by_device_flow(flow)

        _save_cache(cache)

        if "access_token" in result:
            self.stdout.write(self.style.SUCCESS("Microsoft Graph authentication successful. Token cached."))
        else:
            raise RuntimeError(f"Authentication failed: {result}")