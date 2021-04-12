from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcrp.service import Service


class CCAccessToken(Service):
    msg_type = oauth2.CCAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = 'token_endpoint'
    synchronous = True
    service_name = 'accesstoken'
    default_authn_method = 'client_secret_basic'
    http_method = 'POST'
    request_body_type = 'urlencoded'
    response_body_type = 'json'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory, conf=conf)

    def update_service_context(self, resp, key='cc', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.client_get('service_context').state.store_item(resp, 'token_response', key)
