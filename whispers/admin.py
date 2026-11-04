from django.contrib import admin

from .models import ApiToken, Whisper


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


@admin.register(ApiToken)
class ApiTokenAdmin(admin.ModelAdmin):
    """Lists API tokens; deleting one revokes it. Tokens are only issued by sign-in."""

    list_display = (
        "id",
        "user",
        "client_name",
        "scopes",
        "created_at",
        "last_used_at",
        "expires_at",
    )
    list_filter = ("created_at", "expires_at")
    search_fields = ("user__username", "user__email", "client_name")
    exclude = ("token_hash",)
    readonly_fields = (
        "user",
        "client_name",
        "scopes",
        "created_at",
        "last_used_at",
        "expires_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
