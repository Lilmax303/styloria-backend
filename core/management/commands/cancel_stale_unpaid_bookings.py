# core/management/commands/cancel_stale_unpaid_bookings.py

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from core.models import ServiceRequest, Notification


class Command(BaseCommand):
    help = 'Automatically cancel bookings left unpaid for more than 48 hours'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be cancelled without actually cancelling',
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=48,
            help='Hours after which unpaid bookings should be cancelled (default: 48)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        hours_threshold = options['hours']
        
        cutoff_time = timezone.now() - timedelta(hours=hours_threshold)
        
        # Find unpaid bookings older than the threshold
        stale_bookings = ServiceRequest.objects.filter(
            payment_status='unpaid',
            status='pending',
            request_time__lt=cutoff_time,
        )
        
        count = stale_bookings.count()
        
        if count == 0:
            self.stdout.write(self.style.SUCCESS('No stale unpaid bookings found.'))
            return
        
        self.stdout.write(f'Found {count} unpaid booking(s) older than {hours_threshold} hours.')
        
        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN - No changes made.'))
            for booking in stale_bookings:
                age_hours = (timezone.now() - booking.request_time).total_seconds() / 3600
                self.stdout.write(f'  - Booking #{booking.id}: {booking.service_type}, '
                                  f'created {age_hours:.1f} hours ago')
            return
        
        # Cancel the bookings
        cancelled_count = 0
        for booking in stale_bookings:
            try:
                booking.status = 'cancelled'
                booking.cancelled_at = timezone.now()
                booking.cancelled_by = 'system'
                booking.save(update_fields=['status', 'cancelled_at', 'cancelled_by'])
                
                # Notify the user
                Notification.objects.create(
                    user=booking.user,
                    message=(
                        f"Your booking #{booking.id} for {booking.service_type} has been "
                        f"automatically cancelled because it was left unpaid for more than "
                        f"{hours_threshold} hours."
                    ),
                )
                
                cancelled_count += 1
                self.stdout.write(f'  ✓ Cancelled booking #{booking.id}')
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'  ✗ Failed to cancel booking #{booking.id}: {e}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully cancelled {cancelled_count} booking(s).')
        )