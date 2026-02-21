# ============================================================
# File: core/management/commands/generate_referral_codes.py
# ============================================================

from django.core.management.base import BaseCommand
from core.models import CustomUser


class Command(BaseCommand):
    help = (
        'Generate new-format referral codes for existing users.\n'
        'Use --all to regenerate ALL codes (including existing ones).\n'
        'Default: only generates for users who have no code yet.'
    )

    def add_arguments(self, parser):
        parser.add_argument(
            '--all',
            action='store_true',
            default=False,
            help='Regenerate codes for ALL users (replaces old STYLORIA-USERNAME codes)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            default=False,
            help='Preview changes without saving to DB',
        )

    def handle(self, *args, **options):
        regen_all = options['all']
        dry_run = options['dry_run']

        if regen_all:
            users = CustomUser.objects.filter(
                is_active=True
            ).exclude(
                first_name='',
                first_name__isnull=True,
            )
            self.stdout.write(
                self.style.WARNING(
                    f"Regenerating codes for ALL {users.count()} active users with first_name"
                )
            )
        else:
            users = CustomUser.objects.filter(referral_code__isnull=True)
            self.stdout.write(f"Found {users.count()} users without referral codes")

        # Also include users with old-format codes (STYLORIA-*)
        if regen_all:
            old_format = CustomUser.objects.filter(
                referral_code__startswith='STYLORIA-'
            )
            old_count = old_format.count()
            if old_count:
                self.stdout.write(
                    self.style.WARNING(
                        f"  Including {old_count} users with old STYLORIA-* format codes"
                    )
                )

        generated = 0
        skipped = 0
        errors = 0

        for user in users.iterator(chunk_size=200):
            # Need at least first_name and username for the algorithm
            if not (user.first_name or '').strip() or not (user.username or '').strip():
                self.stdout.write(
                    self.style.WARNING(
                        f"  SKIP {user.username} (pk={user.pk}): missing first_name or username"
                    )
                )
                skipped += 1
                continue

            old_code = user.referral_code or '(none)'

            try:
                new_code = user.generate_referral_code()

                if dry_run:
                    self.stdout.write(
                        f"  [DRY RUN] {user.username}: {old_code} → {new_code}"
                    )
                else:
                    user.referral_code = new_code
                    user.save(update_fields=['referral_code'])
                    self.stdout.write(
                        f"  ✅ {user.username}: {old_code} → {new_code}"
                    )

                generated += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f"  ❌ {user.username} (pk={user.pk}): {e}"
                    )
                )
                errors += 1

        # Summary
        self.stdout.write('')
        if dry_run:
            self.stdout.write(
                self.style.SUCCESS(
                    f"DRY RUN complete: {generated} would be generated, "
                    f"{skipped} skipped, {errors} errors"
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Done: {generated} generated, {skipped} skipped, {errors} errors"
                )
            )