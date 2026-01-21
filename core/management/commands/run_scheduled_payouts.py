# core/management/commands/run_scheduled_payouts.py


from decimal import Decimal
from django.core.management.base import BaseCommand
from django.utils import timezone

from core.models import ProviderWallet, ProviderPayoutSettings
from core.services.payouts import payout_wallet_routed, release_matured_pending_balances


class Command(BaseCommand):
    help = "Run scheduled auto-payouts according to ProviderPayoutSettings."

    def handle(self, *args, **options):
        now = timezone.now()
        released = release_matured_pending_balances(now=now)
        weekday = now.weekday()
        hour = now.hour
        day_of_month = now.day

        success = 0
        checked = 0
        skipped = 0

        # Get all providers with auto-payout enabled
        all_settings = ProviderPayoutSettings.objects.select_related("provider").filter(
            auto_payout_enabled=True,
        )

        for s in all_settings:
            # Determine payout frequency (default to weekly for backwards compatibility)
            frequency = getattr(s, "payout_frequency", "weekly") or "weekly"
            
            should_payout = False
            
            if frequency == "weekly":
                # Weekly: check weekday and hour match
                # Valid days are: Tuesday (1), Thursday (3), Friday (4)
                if s.payout_weekday == weekday and s.payout_hour_utc == hour:
                    should_payout = True
                    
            elif frequency == "monthly":
                # Monthly: 1st of every month at provider's preferred hour
                if day_of_month == 1 and s.payout_hour_utc == hour:
                    should_payout = True
            
            if not should_payout:
                skipped += 1
                continue

            provider = s.provider
            

            wallets = ProviderWallet.objects.filter(provider=provider)
            for w in wallets:
                checked += 1
                if w.available_balance <= Decimal("0.00"):
                    continue

                threshold = Decimal(str(s.minimum_payout_amount or "0"))
                if threshold and w.available_balance < threshold:
                    continue

                try:
                    payout_wallet_routed(
                        provider=provider,
                        currency=w.currency,
                        amount=w.available_balance,
                        method=frequency,  # Use the frequency as the method for tracking
                    )
                    success += 1
                except Exception as e:
                    self.stderr.write(f"Auto-payout failed provider={provider.id} currency={w.currency}: {e}")

            s.last_auto_payout_at = now
            # Reset instant payout counter when scheduled payout runs
            s.reset_instant_payout_counter()
            s.save(update_fields=["last_auto_payout_at"])

        self.stdout.write(self.style.SUCCESS(
            f"Auto-payout run complete. "
            f"providers_checked={all_settings.count()} "
            f"providers_skipped={skipped} "
            f"wallets_checked={checked} "
            f"payouts_success={success} "
            f"released_pending_entries={released}"
        ))