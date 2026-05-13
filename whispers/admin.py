from django.contrib import admin

from .models import Whisper


@admin.register(Whisper)
class WhisperAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "mode",
        "created_at",
        "expiry_option",
        "max_views",
        "allowed_cidr",
    )
    list_filter = ("mode", "max_views", "expiry_option")
    readonly_fields = (
        "id",
        "created_at",
        "max_views",
        "mode",
        "allowed_cidr",
    )  # noqa: E501
    search_fields = ("id",)
