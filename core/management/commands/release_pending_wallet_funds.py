# core/management/commands/release_pending_wallet_funds.py


from django.core.management.base import BaseCommand
from core.services.payouts import release_matured_pending_balances

class Command(BaseCommand):
    help = "Move matured pending wallet credits to available balance (cooldown release)."

    def handle(self, *args, **options):
        moved = release_matured_pending_balances()
        self.stdout.write(self.style.SUCCESS(f"Released {moved} pending ledger entries to available."))