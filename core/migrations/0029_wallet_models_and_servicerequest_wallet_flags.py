# core/migrations/0029_wallet_models_and_servicerequest_wallet_flags.py

from django.db import migrations, models
import django.db.models.deletion
from decimal import Decimal


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0028_servicerequest_stripe_tip_payment_intent_id_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="servicerequest",
            name="wallet_credited",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="servicerequest",
            name="wallet_credited_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="ProviderWallet",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("currency", models.CharField(default="USD", max_length=3)),
                ("available_balance", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("pending_balance", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("lifetime_earnings", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("lifetime_payouts", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("provider", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="wallets", to="core.serviceprovider")),
            ],
            options={"unique_together": {("provider", "currency")}},
        ),
        migrations.CreateModel(
            name="Payout",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("currency", models.CharField(default="USD", max_length=3)),
                ("gross_amount", models.DecimalField(decimal_places=2, max_digits=12)),
                ("fee_amount", models.DecimalField(decimal_places=2, default=Decimal("0.00"), max_digits=12)),
                ("net_amount", models.DecimalField(decimal_places=2, max_digits=12)),
                ("method", models.CharField(choices=[("weekly", "Weekly"), ("instant", "Instant"), ("manual", "Manual")], default="weekly", max_length=10)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("processing", "Processing"), ("paid", "Paid"), ("failed", "Failed"), ("canceled", "Canceled")], default="queued", max_length=12)),
                ("stripe_transfer_id", models.CharField(blank=True, max_length=100, null=True)),
                ("failure_reason", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("processed_at", models.DateTimeField(blank=True, null=True)),
                ("provider", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="payouts", to="core.serviceprovider")),
            ],
        ),
        migrations.CreateModel(
            name="WalletLedgerEntry",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("direction", models.CharField(choices=[("credit", "Credit"), ("debit", "Debit")], max_length=6)),
                ("kind", models.CharField(choices=[("earning", "Earning"), ("payout", "Payout"), ("fee", "Fee"), ("adjustment", "Adjustment"), ("refund", "Refund")], max_length=12)),
                ("amount", models.DecimalField(decimal_places=2, max_digits=12)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("available", "Available"), ("paid", "Paid"), ("reversed", "Reversed")], default="pending", max_length=10)),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                ("available_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("payout", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="ledger_entries", to="core.payout")),
                ("service_request", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="wallet_entries", to="core.servicerequest")),
                ("wallet", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="entries", to="core.providerwallet")),
            ],
        ),
        migrations.AddIndex(
            model_name="walletledgerentry",
            index=models.Index(fields=["status", "available_at"], name="core_walletl_status_8f61f2_idx"),
        ),
        migrations.AddIndex(
            model_name="providerwallet",
            index=models.Index(fields=["provider", "currency"], name="core_provid_provider_8a15d6_idx"),
        ),
    ]