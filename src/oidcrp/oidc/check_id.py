import logging

from oidcmsg.client.service import Service
from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import session

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class CheckID(Service):
    msg_type = session.CheckIDRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ''
    synchronous = True
    service_name = 'check_id'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory,
                         conf=conf)
        self.pre_construct = [self.oidc_pre_construct]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        request_args = self.client_get("service_context").state.multiple_extend_request_args(
            request_args, kwargs['state'], ['id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])
        return request_args, {}
