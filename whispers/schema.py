def versioned_endpoints_only(endpoints, **kwargs):
    """drf-spectacular hook that documents only the versioned API, not its aliases."""
    return [endpoint for endpoint in endpoints if endpoint[0].startswith("/api/v1/")]
