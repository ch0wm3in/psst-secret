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
    max_views = serializers.IntegerField(
        default=1,
        min_value=0,
        max_value=100,
        help_text="Reveals before self-destruction. 1 = burn after read; 0 = unlimited.",
    )
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
    public_key = serializers.CharField(
        max_length=2000,
        help_text="X-Wing (ML-KEM-768 + X25519) public key, base64.",
    )
    salt = serializers.CharField(max_length=50, default="", allow_blank=True)
    wrapped_key = serializers.CharField(
        max_length=500,
        default="",
        allow_blank=True,
        help_text="Request private key encrypted with a password-derived key.",
    )
    wrapped_key_iv = serializers.CharField(max_length=50, default="", allow_blank=True)
    max_views = serializers.IntegerField(
        default=1,
        min_value=0,
        max_value=100,
        help_text="Reveals before self-destruction. 1 = burn after read; 0 = unlimited.",
    )
    expiry = serializers.ChoiceField(
        choices=list(EXPIRY_DELTAS.keys()), default="1d"
    )  # noqa: E501
    allowed_cidr = CIDRField(default="", allow_blank=True)
    require_auth_view = serializers.BooleanField(default=False)
    require_auth_submit = serializers.BooleanField(default=False)
    notify_email = serializers.EmailField(default="", allow_blank=True)

    def validate(self, attrs):
        fields = (attrs["salt"], attrs["wrapped_key"], attrs["wrapped_key_iv"])
        if any(fields) and not all(fields):
            raise serializers.ValidationError(
                "salt, wrapped_key and wrapped_key_iv must be provided together"
            )
        return attrs


class CreateRequestResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField()
    submit_url = serializers.URLField()
    view_url = serializers.URLField()


class SubmitWhisperSerializer(serializers.Serializer):
    ciphertext = serializers.CharField(max_length=70_000_000)
    iv = serializers.CharField(max_length=50)
    encapsulated_key = serializers.CharField(max_length=2000)


class RevealWhisperResponseSerializer(serializers.Serializer):
    ciphertext = serializers.CharField()
    iv = serializers.CharField()
    salt = serializers.CharField()
    encapsulated_key = serializers.CharField(allow_blank=True)
    wrapped_key = serializers.CharField(allow_blank=True)
    wrapped_key_iv = serializers.CharField(allow_blank=True)
    view_count = serializers.IntegerField()
    max_views = serializers.IntegerField()
    remaining_views = serializers.IntegerField()


class SubmitWhisperResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
