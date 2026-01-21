# core/management/commands/run_weekly_payouts.py


from decimal import Decimal
from django.core.management.base import BaseCommand
from core.models import ServiceProvider, ProviderWallet
from core.services.payouts import payout_wallet_routed

class Command(BaseCommand):
    help = "Run weekly payouts for all providers: payout full available balance per currency."

    def handle(self, *args, **options):
        total = 0
        for wallet in ProviderWallet.objects.select_related("provider").all():
            if wallet.available_balance <= Decimal("0.00"):
                continue
            provider = wallet.provider
            if not provider:
                continue

            try:
                payout_wallet_routed(provider=provider, currency=wallet.currency, amount=wallet.available_balance, method="weekly")
                total += 1
            except Exception as e:
                self.stderr.write(f"Weekly payout failed for provider={provider.id} {wallet.currency}: {e}")

        self.stdout.write(self.style.SUCCESS(f"Weekly payouts completed. Success count={total}"))