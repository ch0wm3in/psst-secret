import uuid

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Whisper",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("mode", models.CharField(choices=[("send", "Send"), ("receive", "Receive")], default="send", max_length=7)),
                ("burn_after_read", models.BooleanField(default=False)),
                ("allowed_cidr", models.CharField(blank=True, default="", help_text="IP or CIDR restricting who can view (send) or submit (receive)", max_length=43)),
                ("expiry_option", models.CharField(choices=[("5m", "5 Minutes"), ("1h", "1 Hour"), ("1d", "1 Day"), ("1w", "1 Week"), ("1M", "1 Month")], default="1d", max_length=5)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
