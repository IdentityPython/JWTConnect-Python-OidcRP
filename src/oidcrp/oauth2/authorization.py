"""The service that talks to the OAuth2 Authorization endpoint."""
import logging

from oidcmsg import oauth2
from oidcmsg.exception import MissingParameter
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.time_util import time_sans_frac

from oidcrp.oauth2.utils import get_state_parameter
from oidcrp.oauth2.utils import pick_redirect_uris
from oidcrp.oauth2.utils import set_state_parameter
from oidcrp.service import Service

LOGGER = logging.getLogger(__name__)


class Authorization(Service):
    """The service that talks to the OAuth2 Authorization endpoint."""
    msg_type = oauth2.AuthorizationRequest
    response_cls = oauth2.AuthorizationResponse
    error_msg = ResponseMessage
    endpoint_name = 'authorization_endpoint'
    synchronous = False
    service_name = 'authorization'
    response_body_type = 'urlencoded'

    # parameter = Service.parameter.copy()
    # parameter.update({
    #     "endpoint": ""
    # })

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory, conf=conf)
        self.pre_construct.extend([pick_redirect_uris, set_state_parameter])
        self.post_construct.append(self.store_auth_request)

    def update_service_context(self, resp, key='', **kwargs):
        if 'expires_in' in resp:
            resp['__expires_at'] = time_sans_frac() + int(resp['expires_in'])
        self.client_get("service_context").state.store_item(resp, 'auth_response', key)

    def store_auth_request(self, request_args=None, **kwargs):
        """Store the authorization request in the state DB."""
        _key = get_state_parameter(request_args, kwargs)
        self.client_get("service_context").state.store_item(request_args, 'auth_request', _key)
        return request_args

    def gather_request_args(self, **kwargs):
        ar_args = Service.gather_request_args(self, **kwargs)

        if 'redirect_uri' not in ar_args:
            try:
                ar_args['redirect_uri'] = self.client_get("service_context").redirect_uris[0]
            except (KeyError, AttributeError):
                raise MissingParameter('redirect_uri')

        return ar_args

    def post_parse_response(self, response, **kwargs):
        """
        Add scope claim to response, from the request, if not present in the
        response

        :param response: The response
        :param kwargs: Extra Keyword arguments
        :return: A possibly augmented response
        """

        if "scope" not in response:
            try:
                _key = kwargs['state']
            except KeyError:
                pass
            else:
                if _key:
                    item = self.client_get("service_context").state.get_item(oauth2.AuthorizationRequest,
                                                                     'auth_request', _key)
                    try:
                        response["scope"] = item["scope"]
                    except KeyError:
                        pass
        return response
