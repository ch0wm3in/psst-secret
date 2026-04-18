from django.contrib import admin

from .models import Whisper


@admin.register(Whisper)
class WhisperAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "mode",
        "created_at",
        "expiry_option",
        "burn_after_read",
        "allowed_cidr",
    )
    list_filter = ("mode", "burn_after_read", "expiry_option")
    readonly_fields = (
        "id",
        "created_at",
        "burn_after_read",
        "mode",
        "allowed_cidr",
    )  # noqa: E501
    search_fields = ("id",)
