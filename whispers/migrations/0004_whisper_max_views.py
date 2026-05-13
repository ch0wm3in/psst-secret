from django.db import migrations, models


def burn_to_max_views(apps, schema_editor):
    Whisper = apps.get_model("whispers", "Whisper")
    # burn_after_read=True  -> max_views=1 (destroy after first reveal)
    # burn_after_read=False -> max_views=0 (legacy behavior: no view-based destruction)
    Whisper.objects.filter(burn_after_read=True).update(max_views=1)
    Whisper.objects.filter(burn_after_read=False).update(max_views=0)


def max_views_to_burn(apps, schema_editor):
    Whisper = apps.get_model("whispers", "Whisper")
    Whisper.objects.filter(max_views=1).update(burn_after_read=True)
    Whisper.objects.exclude(max_views=1).update(burn_after_read=False)


class Migration(migrations.Migration):

    dependencies = [
        ("whispers", "0003_whisper_notify_email"),
    ]

    operations = [
        migrations.AddField(
            model_name="whisper",
            name="max_views",
            field=models.PositiveIntegerField(
                default=1,
                help_text=(
                    "Number of successful reveals before the whisper self-destructs. "
                    "1 = burn after first read; 0 = unlimited (no view-based destruction)."
                ),
            ),
        ),
        migrations.RunPython(burn_to_max_views, max_views_to_burn),
        migrations.RemoveField(
            model_name="whisper",
            name="burn_after_read",
        ),
    ]
