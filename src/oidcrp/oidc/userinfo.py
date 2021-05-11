import logging

from oidcmsg import oidc
from oidcmsg.exception import MissingSigningKey
from oidcmsg.message import Message

from oidcrp.oauth2.utils import get_state_parameter
from oidcrp.service import Service

logger = logging.getLogger(__name__)

UI2REG = {
    'sigalg': 'userinfo_signed_response_alg',
    'encalg': 'userinfo_encrypted_response_alg',
    'encenc': 'userinfo_encrypted_response_enc'
}


def carry_state(request_args=None, **kwargs):
    """
    Make sure post_construct_methods have access to state

    :param request_args:
    :param kwargs:
    :return: The value of the state parameter
    """
    return request_args, {'state': get_state_parameter(request_args, kwargs)}


class UserInfo(Service):
    msg_type = Message
    response_cls = oidc.OpenIDSchema
    error_msg = oidc.ResponseMessage
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    service_name = 'userinfo'
    default_authn_method = 'bearer_header'
    http_method = 'GET'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory,
                         conf=conf)
        self.pre_construct = [self.oidc_pre_construct, carry_state]

    def oidc_pre_construct(self, request_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        if "access_token" in request_args:
            pass
        else:
            request_args = self.client_get("service_context").state.multiple_extend_request_args(
                request_args, kwargs['state'], ['access_token'],
                ['auth_response', 'token_response', 'refresh_token_response']
            )

        return request_args, {}

    def post_parse_response(self, response, **kwargs):
        _context = self.client_get("service_context")
        _state_interface = _context.state
        _args = _state_interface.multiple_extend_request_args(
            {}, kwargs['state'], ['id_token'],
            ['auth_response', 'token_response', 'refresh_token_response']
        )

        try:
            _sub = _args['id_token']['sub']
        except KeyError:
            logger.warning("Can not verify value on sub")
        else:
            if response['sub'] != _sub:
                raise ValueError('Incorrect "sub" value')

        try:
            _csrc = response["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "JWT" in spec:
                    try:
                        aggregated_claims = Message().from_jwt(
                            spec["JWT"].encode("utf-8"),
                            keyjar=_context.keyjar)
                    except MissingSigningKey as err:
                        logger.warning(
                            'Error encountered while unpacking aggregated '
                            'claims'.format(err))
                    else:
                        claims = [value for value, src in
                                  response["_claim_names"].items() if
                                  src == csrc]

                        for key in claims:
                            response[key] = aggregated_claims[key]
                elif 'endpoint' in spec:
                    _info = {
                        "headers": self.get_authn_header(
                            {}, self.default_authn_method,
                            authn_endpoint=self.endpoint_name,
                            key=kwargs["state"]
                        ),
                        "url": spec["endpoint"]
                    }

        _state_interface.store_item(response, 'user_info', kwargs['state'])
        return response

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """
        _context = self.client_get("service_context")
        kwargs = {
            'client_id': _context.client_id,
            'iss': _context.issuer,
            'keyjar': _context.keyjar, 'verify': True,
            'skew': _context.clock_skew
        }

        _reg_resp = _context.registration_response
        if _reg_resp:
            for attr, param in UI2REG.items():
                try:
                    kwargs[attr] = _reg_resp[param]
                except KeyError:
                    pass

        try:
            kwargs['allow_missing_kid'] = _context.allow['missing_kid']
        except KeyError:
            pass

        return kwargs

