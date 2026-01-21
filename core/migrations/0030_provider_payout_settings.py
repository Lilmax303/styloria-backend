# core/migrations/0030_provider_payout_settings.py


from django.db import migrations, models
import django.db.models.deletion
from decimal import Decimal


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0029_wallet_models_and_servicerequest_wallet_flags"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProviderPayoutSettings",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("auto_payout_enabled", models.BooleanField(default=True)),
                ("payout_weekday", models.PositiveSmallIntegerField(default=0)),
                ("payout_hour_utc", models.PositiveSmallIntegerField(default=2)),
                ("minimum_payout_amount", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("instant_payout_enabled", models.BooleanField(default=True)),
                ("last_auto_payout_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("provider", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="payout_settings", to="core.serviceprovider")),
            ],
        ),
        migrations.AddIndex(
            model_name="providerpayoutsettings",
            index=models.Index(fields=["auto_payout_enabled", "payout_weekday"], name="core_payout_auto_weekday_idx"),
        ),
    ]