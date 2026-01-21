# core/management/commands/cleanup_password_reset_codes.py

from django.core.management.base import BaseCommand
from core.models import PasswordResetCode


class Command(BaseCommand):
    help = "Delete expired password reset codes older than N days"

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Delete codes older than this many days (default: 7)',
        )

    def handle(self, *args, **options):
        days = options['days']
        deleted_count = PasswordResetCode.objects.cleanup_expired(days=days)
        self.stdout.write(
            self.style.SUCCESS(f"Deleted {deleted_count} expired password reset codes (older than {days} days)")
        )