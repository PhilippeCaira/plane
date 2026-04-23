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
        # Skip healthcheck interne (wget depuis 127.0.0.1) pour que Docker
        # healthcheck reçoive 200, pas 302 → container stay healthy.
        ua = request.META.get("HTTP_USER_AGENT", "")
        is_internal_hc = (
            request.META.get("REMOTE_ADDR") in ("127.0.0.1", "::1")
            and ("Wget" in ua or ua.startswith("curl/"))
        )
        import sys
        oidc_on = os.environ.get("OIDC_AUTO_REDIRECT") == "true"
        in_root = request.path in self.ROOT_PATHS
        is_get = request.method == "GET"
        authed = hasattr(request, "user") and request.user.is_authenticated
        print(
            f"[auto_oidc] path={request.path!r} ua={ua!r} remote={request.META.get('REMOTE_ADDR')} "
            f"oidc_on={oidc_on} internal_hc={is_internal_hc} in_root={in_root} "
            f"is_get={is_get} authed={authed}",
            file=sys.stderr, flush=True,
        )
        if (
            oidc_on
            and not is_internal_hc
            and is_get
            and in_root
            and request.GET.get("local") != "1"
            and not authed
        ):
            return HttpResponseRedirect("/auth/zitadel/")
        return self.get_response(request)
