"""Implements the service that talks to the Access Token endpoint."""
import logging

from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcrp.oauth2.utils import get_state_parameter
from oidcrp.service import Service

LOGGER = logging.getLogger(__name__)


class AccessToken(Service):
    """The access token service."""
    msg_type = oauth2.AccessTokenRequest
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
        self.pre_construct.append(self.oauth_pre_construct)

    def update_service_context(self, resp, key='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.client_get("service_context").state.store_item(resp, 'token_response', key)

    def oauth_pre_construct(self, request_args=None, post_args=None, **kwargs):
        """

        :param request_args: Initial set of request arguments
        :param kwargs: Extra keyword arguments
        :return: Request arguments
        """
        _state = get_state_parameter(request_args, kwargs)
        parameters = list(self.msg_type.c_param.keys())

        _context = self.client_get("service_context")
        _args = _context.state.extend_request_args({}, oauth2.AuthorizationRequest,
                                                   'auth_request', _state, parameters)

        _args = _context.state.extend_request_args(_args, oauth2.AuthorizationResponse,
                                                   'auth_response', _state, parameters)

        if "grant_type" not in _args:
            _args["grant_type"] = "authorization_code"

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, post_args
