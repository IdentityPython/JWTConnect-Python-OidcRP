from oidcmsg.client.service import Service
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc.backchannel_authentication import AuthenticationRequest
from oidcmsg.oidc.backchannel_authentication import AuthenticationRequestResponse


class Authentication(Service):
    msg_type = AuthenticationRequest
    response_cls = AuthenticationRequestResponse
    error_msg = ResponseMessage
    endpoint_name = 'backchannel_authentication'
    synchronous = True
    service_name = 'backchannel_authentication'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory, conf=conf)
        self.default_request_args = {'scope': ['openid']}
        self.pre_construct = []
        self.post_construct = []
