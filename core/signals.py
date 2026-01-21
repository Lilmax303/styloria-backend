# core/signals.py


from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import CustomUser, ServiceProvider

@receiver(post_save, sender=CustomUser)
def ensure_provider_profile(sender, instance: CustomUser, created, **kwargs):
    if instance.role == "provider":
        ServiceProvider.objects.get_or_create(
            user=instance,
            defaults={
                "available": False,
                "verification_status": "not_submitted",
                "is_verified": False,
            },
        )