# ruff: noqa: D100, D101, D102
"""Auto-redirect non-authenticated root requests to the Zitadel OIDC flow.

Activated when OIDC_AUTO_REDIRECT=true in the environment. Preserves an
escape hatch via ?local=1 for admin debug (keeps Plane's welcome/sign-in
pages reachable when needed).
"""
import os

from django.http import HttpResponseRedirect


class AutoOIDCRedirectMiddleware:
    ROOT_PATHS = ("/", "")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip healthcheck interne (wget/curl localhost) pour que Docker
        # healthcheck reçoive 200, pas 302 → container stay healthy.
        ua = request.META.get("HTTP_USER_AGENT", "")
        is_internal_hc = (
            request.META.get("REMOTE_ADDR") in ("127.0.0.1", "::1")
            or "Wget" in ua
            or "curl" in ua.lower()
        )
        if (
            os.environ.get("OIDC_AUTO_REDIRECT") == "true"
            and not is_internal_hc
            and request.method == "GET"
            and request.path in self.ROOT_PATHS
            and request.GET.get("local") != "1"
            and (not hasattr(request, "user") or not request.user.is_authenticated)
        ):
            return HttpResponseRedirect("/auth/zitadel/")
        return self.get_response(request)
