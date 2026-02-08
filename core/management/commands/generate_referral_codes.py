# ============================================================
# File: core/management/commands/generate_referral_codes.py
# ============================================================

from django.core.management.base import BaseCommand
from core.models import CustomUser


class Command(BaseCommand):
    help = 'Generate referral codes for existing users who do not have one'

    def handle(self, *args, **options):
        users_without_code = CustomUser.objects.filter(referral_code__isnull=True)
        count = users_without_code.count()
        
        self.stdout.write(f"Found {count} users without referral codes")
        
        for user in users_without_code:
            user.referral_code = user.generate_referral_code()
            user.save(update_fields=['referral_code'])
            self.stdout.write(f"  Generated code for {user.username}: {user.referral_code}")
        
        self.stdout.write(self.style.SUCCESS(f"Successfully generated {count} referral codes"))