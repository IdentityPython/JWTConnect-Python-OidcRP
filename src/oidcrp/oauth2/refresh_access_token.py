"""The service that talks to the OAuth2 refresh access token endpoint."""
import logging

from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcrp.oauth2.utils import get_state_parameter
from oidcrp.service import Service

LOGGER = logging.getLogger(__name__)


class RefreshAccessToken(Service):
    """The service that talks to the OAuth2 refresh access token endpoint."""
    msg_type = oauth2.RefreshAccessTokenRequest
    response_cls = oauth2.AccessTokenResponse
    error_msg = ResponseMessage
    endpoint_name = 'token_endpoint'
    synchronous = True
    service_name = 'refresh_token'
    default_authn_method = 'bearer_header'
    http_method = 'POST'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.client_get("service_context").state.store_item(resp, 'token_response', key)

    def oauth_pre_construct(self, request_args=None, **kwargs):
        """Preconstructor of request arguments"""
        _state = get_state_parameter(request_args, kwargs)
        parameters = list(self.msg_type.c_param.keys())

        _si = self.client_get("service_context").state
        _args = _si.extend_request_args({}, oauth2.AccessTokenResponse,
                                        'token_response', _state, parameters)

        _args = _si.extend_request_args(_args, oauth2.AccessTokenResponse,
                                        'refresh_token_response', _state,
                                        parameters)

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, {}
