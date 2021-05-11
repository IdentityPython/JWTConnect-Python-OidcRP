from oidcmsg import oidc

from oidcrp.oauth2 import refresh_access_token


class RefreshAccessToken(refresh_access_token.RefreshAccessToken):
    msg_type = oidc.RefreshAccessTokenRequest
    response_cls = oidc.AccessTokenResponse
    error_msg = oidc.ResponseMessage

    def get_authn_method(self):
        try:
            return self.client_get("service_context").behaviour['token_endpoint_auth_method']
        except KeyError:
            return self.default_authn_method
