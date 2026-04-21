# Zitadel OIDC provider for Plane CE (fork PhilippeCaira/plane branch oidc)
# Based on google.py pattern, endpoints pointing to Zitadel.

import os
import uuid
from datetime import datetime
from urllib.parse import urlencode

import pytz

from plane.authentication.adapter.oauth import OauthAdapter
from plane.authentication.adapter.error import (
    AUTHENTICATION_ERROR_CODES,
    AuthenticationException,
)
from plane.license.utils.instance_value import get_configuration_value


class ZitadelOAuthProvider(OauthAdapter):
    provider = "zitadel"
    scope = "openid profile email"

    def __init__(self, request, code=None, state=None, callback=None):
        (CLIENT_ID, CLIENT_SECRET, ISSUER) = get_configuration_value(
            [
                {"key": "OIDC_CLIENT_ID", "default": os.environ.get("OIDC_CLIENT_ID")},
                {"key": "OIDC_CLIENT_SECRET", "default": os.environ.get("OIDC_CLIENT_SECRET")},
                {"key": "OIDC_ISSUER", "default": os.environ.get("OIDC_ISSUER")},
            ]
        )

        if not (CLIENT_ID and CLIENT_SECRET and ISSUER):
            raise AuthenticationException(
                error_code=AUTHENTICATION_ERROR_CODES.get("OAUTH_NOT_CONFIGURED", 5080),
                error_message="OIDC_NOT_CONFIGURED",
            )

        self.token_url = f"{ISSUER.rstrip('/')}/oauth/v2/token"
        self.userinfo_url = f"{ISSUER.rstrip('/')}/oidc/v1/userinfo"
        self.auth_base_url = f"{ISSUER.rstrip('/')}/oauth/v2/authorize"

        redirect_uri = f"""{"https" if request.is_secure() else "http"}://{request.get_host()}/auth/zitadel/callback/"""
        url_params = {
            "client_id": CLIENT_ID,
            "scope": self.scope,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": state,
        }
        auth_url = f"{self.auth_base_url}?{urlencode(url_params)}"

        super().__init__(
            request,
            self.provider,
            CLIENT_ID,
            self.scope,
            redirect_uri,
            auth_url,
            self.token_url,
            self.userinfo_url,
            CLIENT_SECRET,
            code,
            callback=callback,
        )

    def set_token_data(self):
        data = {
            "code": self.code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code",
        }
        token_response = self.get_user_token(data=data)
        super().set_token_data(
            {
                "access_token": token_response.get("access_token"),
                "refresh_token": token_response.get("refresh_token", None),
                "access_token_expired_at": (
                    datetime.fromtimestamp(token_response.get("expires_in"), tz=pytz.utc)
                    if token_response.get("expires_in")
                    else None
                ),
                "refresh_token_expired_at": None,
                "id_token": token_response.get("id_token", ""),
            }
        )

    def set_user_data(self):
        ui = self.get_user_response()
        user_data = {
            "email": ui.get("email"),
            "user": {
                "avatar": ui.get("picture"),
                "first_name": ui.get("given_name") or ui.get("name") or "",
                "last_name": ui.get("family_name") or "",
                "provider_id": ui.get("sub"),
                "is_password_autoset": True,
            },
        }
        super().set_user_data(user_data)
