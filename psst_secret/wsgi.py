"""
WSGI config for psst-secret project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application
from granian.utils.proxies import wrap_wsgi_with_proxy_headers

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "psst_secret.settings")

application = get_wsgi_application()
# We assume that people are using sane reverse proxies that set the standard headers, so we trust all hosts here.
application = wrap_wsgi_with_proxy_headers(
    application, trusted_hosts=os.environ.get("GRANIAN_TRUSTED_HOSTS", "*").split(",")
)
