from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcrp.service import Service


class CCRefreshAccessToken(Service):
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
        self.pre_construct.append(self.cc_pre_construct)
        self.post_construct.append(self.cc_post_construct)

    def cc_pre_construct(self, request_args=None, **kwargs):
        _state_id = kwargs.get("state", "cc")
        parameters = ['refresh_token']
        _state_interface = self.client_get("service_context").state
        _args = _state_interface.extend_request_args({}, oauth2.AccessTokenResponse,
                                                     'token_response', _state_id, parameters)

        _args = _state_interface.extend_request_args(_args, oauth2.AccessTokenResponse,
                                                     'refresh_token_response', _state_id,
                                                     parameters)

        if request_args is None:
            request_args = _args
        else:
            _args.update(request_args)
            request_args = _args

        return request_args, {}

    def cc_post_construct(self, request_args, **kwargs):
        for attr in ['client_id', 'client_secret']:
            try:
                del request_args[attr]
            except KeyError:
                pass

        return request_args

    def update_service_context(self, resp, key='cc', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.client_get("service_context").state.store_item(resp, 'token_response', key)
