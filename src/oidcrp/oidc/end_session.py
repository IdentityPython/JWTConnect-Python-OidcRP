import logging

from oidcmsg.oauth2 import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import session

from oidcrp.service import Service
from oidcrp.util import rndstr

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)


class EndSession(Service):
    msg_type = session.EndSessionRequest
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = 'end_session_endpoint'
    synchronous = True
    service_name = 'end_session'
    response_body_type = 'html'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory,
                         conf=conf)
        self.pre_construct = [self.get_id_token_hint,
                              self.add_post_logout_redirect_uri,
                              self.add_state]

    def get_id_token_hint(self, request_args=None, **kwargs):
        """
        Add id_token_hint to request

        :param request_args:
        :param kwargs:
        :return:
        """
        request_args = self.client_get("service_context").state.multiple_extend_request_args(
            request_args, kwargs['state'], ['id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'],
            orig=True
        )

        try:
            request_args['id_token_hint'] = request_args['id_token']
        except KeyError:
            pass
        else:
            del request_args['id_token']

        return request_args, {}

    def add_post_logout_redirect_uri(self, request_args=None, **kwargs):
        if 'post_logout_redirect_uri' not in request_args:
            try:
                request_args[
                    'post_logout_redirect_uri'
                ] = self.client_get("service_context").register_args[
                    'post_logout_redirect_uris'][0]
            except KeyError:
                pass

        return request_args, {}

    def add_state(self, request_args=None, **kwargs):
        if 'state' not in request_args:
            request_args['state'] = rndstr(32)

        # As a side effect bind logout state to session state
        self.client_get("service_context").state.store_logout_state2state(request_args['state'],
                                                                          kwargs['state'])

        return request_args, {}
