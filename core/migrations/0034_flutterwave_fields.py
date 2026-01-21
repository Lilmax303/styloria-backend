from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0033_rename_core_payout_auto_weekday_idx_core_provid_auto_pa_ef9e9c_idx"),
    ]

    operations = [
        migrations.AddField(
            model_name="servicerequest",
            name="payment_gateway",
            field=models.CharField(blank=True, default="", help_text="Payment gateway used for this booking (stripe|flutterwave).", max_length=20),
        ),
        migrations.AddField(
            model_name="servicerequest",
            name="flutterwave_tx_ref",
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
        migrations.AddField(
            model_name="servicerequest",
            name="flutterwave_transaction_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="servicerequest",
            name="flutterwave_fee_amount",
            field=models.DecimalField(blank=True, decimal_places=2, help_text="Flutterwave processing fee (if available).", max_digits=10, null=True),
        ),
    ]