import ipaddress

from rest_framework import serializers

from .constants import EXPIRY_DELTAS, SUPPORTED_FORMAT_VERSIONS


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


class VersionedPayloadSerializer(serializers.Serializer):
    v = serializers.ChoiceField(
        choices=SUPPORTED_FORMAT_VERSIONS,
        required=False,
        help_text="Encryption format version (see docs/format.md). Omitted means legacy version 0.",
    )


class RevealProtectedSerializer(serializers.Serializer):
    reveal_token_hash = serializers.RegexField(
        regex=r"\A[0-9a-f]{64}\Z",
        max_length=64,
        trim_whitespace=False,
        help_text="SHA-256 hex digest of an independent random 256-bit reveal token.",
    )


class CreateWhisperSerializer(VersionedPayloadSerializer, RevealProtectedSerializer):
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


class ReceiveAccessSerializer(serializers.Serializer):
    creator_only = serializers.BooleanField(required=False)
    allowed_reader_emails = serializers.ListField(
        child=serializers.EmailField(max_length=254),
        max_length=20,
        required=False,
    )


class CreateRequestSerializer(
    VersionedPayloadSerializer, ReceiveAccessSerializer, RevealProtectedSerializer
):
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


class SubmitWhisperSerializer(VersionedPayloadSerializer):
    ciphertext = serializers.CharField(max_length=70_000_000)
    iv = serializers.CharField(max_length=50)
    encapsulated_key = serializers.CharField(max_length=2000)


class SubmitRequestKeySerializer(serializers.Serializer):
    public_key = serializers.CharField(
        help_text="X-Wing public key, base64. Check it against the submit link fingerprint."
    )
    v = serializers.IntegerField(help_text="Format version of the request.")


class ApiInfoSerializer(serializers.Serializer):
    server_version = serializers.CharField()
    api_version = serializers.IntegerField()
    format_versions = serializers.ListField(
        child=serializers.IntegerField(),
        help_text="Format versions accepted for new whispers.",
    )


class RevealWhisperResponseSerializer(serializers.Serializer):
    v = serializers.IntegerField(help_text="Format version; 0 for legacy whispers.")
    ciphertext = serializers.CharField()
    iv = serializers.CharField()
    salt = serializers.CharField()
    encapsulated_key = serializers.CharField(allow_blank=True)
    wrapped_key = serializers.CharField(allow_blank=True)
    wrapped_key_iv = serializers.CharField(allow_blank=True)
    view_count = serializers.IntegerField()
    max_views = serializers.IntegerField()
    remaining_views = serializers.IntegerField()


class RevealWhisperSerializer(serializers.Serializer):
    reveal_token = serializers.RegexField(
        regex=r"\A[0-9a-f]{64}\Z",
        max_length=64,
        trim_whitespace=False,
        default="",
        allow_blank=True,
        help_text="Reveal token from the view link fragment, required for token-protected whispers. "
        "Omit only for pre-token whispers. Never send the decryption key.",
    )


class SubmitWhisperResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
