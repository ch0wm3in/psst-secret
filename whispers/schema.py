from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object

from whispers.api_tokens import AUTH_SCHEME


def versioned_endpoints_only(endpoints, **kwargs):
    """drf-spectacular hook that documents only the versioned API, not its aliases."""
    return [endpoint for endpoint in endpoints if endpoint[0].startswith("/api/v1/")]


class BearerTokenScheme(OpenApiAuthenticationExtension):
    target_class = "whispers.api_tokens.BearerTokenAuthentication"
    name = "apiToken"

    def get_security_definition(self, auto_schema):
        return build_bearer_security_scheme_object(
            header_name="AUTHORIZATION", token_prefix=AUTH_SCHEME
        )
