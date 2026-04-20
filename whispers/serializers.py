import ipaddress

from rest_framework import serializers

from .constants import EXPIRY_DELTAS


class CIDRField(serializers.CharField):
    """CharField that validates an optional IP/CIDR value."""

    def to_internal_value(self, data):
        value = super().to_internal_value(data).strip()
        if value:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise serializers.ValidationError("Invalid IP/CIDR") from exc
        return value


class CreateWhisperSerializer(serializers.Serializer):
    ciphertext = serializers.CharField(max_length=70_000_000)
    iv = serializers.CharField(max_length=50)
    salt = serializers.CharField(max_length=50, default="", allow_blank=True)
    burn_after_read = serializers.BooleanField(default=False)
    expiry = serializers.ChoiceField(
        choices=list(EXPIRY_DELTAS.keys()), default="1d"
    )  # noqa: E501
    allowed_cidr = CIDRField(default="", allow_blank=True)
    require_auth_view = serializers.BooleanField(default=False)
    notify_email = serializers.EmailField(default="", allow_blank=True)


class CreateWhisperResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    url = serializers.URLField()


class CreateRequestSerializer(serializers.Serializer):
    salt = serializers.CharField(max_length=50, default="", allow_blank=True)
    password_verify_token = serializers.CharField(
        max_length=500, default="", allow_blank=True
    )
    password_verify_iv = serializers.CharField(
        max_length=50, default="", allow_blank=True
    )
    burn_after_read = serializers.BooleanField(default=False)
    expiry = serializers.ChoiceField(
        choices=list(EXPIRY_DELTAS.keys()), default="1d"
    )  # noqa: E501
    allowed_cidr = CIDRField(default="", allow_blank=True)
    require_auth_view = serializers.BooleanField(default=False)
    require_auth_submit = serializers.BooleanField(default=False)
    notify_email = serializers.EmailField(default="", allow_blank=True)


class CreateRequestResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    submit_url = serializers.URLField()
    view_url = serializers.URLField()


class SubmitWhisperSerializer(serializers.Serializer):
    ciphertext = serializers.CharField(max_length=70_000_000)
    iv = serializers.CharField(max_length=50)


class RevealWhisperResponseSerializer(serializers.Serializer):
    ciphertext = serializers.CharField()
    iv = serializers.CharField()
    salt = serializers.CharField()


class SubmitWhisperResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
