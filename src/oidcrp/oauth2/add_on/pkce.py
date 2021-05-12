import logging

from cryptojwt.utils import b64e
from oidcmsg.message import Message

from oidcrp.defaults import CC_METHOD
from oidcrp.exception import Unsupported
from oidcrp.oauth2.utils import get_state_parameter
from oidcrp.util import unreserved

logger = logging.getLogger(__name__)


def add_code_challenge(request_args, service, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcrp.oidc.service.Authorization` instance

    :param service: The service that uses this function
    :param request_args: Set of request arguments
    :param kwargs: Extra set of keyword arguments
    :return: Updated set of request arguments
    """
    _context = service.client_get("service_context")
    _kwargs = _context.add_on["pkce"]

    try:
        cv_len = _kwargs['code_challenge_length']
    except KeyError:
        cv_len = 64  # Use default

    # code_verifier: string of length cv_len
    code_verifier = unreserved(cv_len)
    _cv = code_verifier.encode()

    try:
        _method = _kwargs['code_challenge_method']
    except KeyError:
        _method = 'S256'

    try:
        # Pick hash method
        _hash_method = CC_METHOD[_method]
        # Use it on the code_verifier
        _hv = _hash_method(_cv).digest()
        # base64 encode the hash value
        code_challenge = b64e(_hv).decode('ascii')
    except KeyError:
        raise Unsupported(
            'PKCE Transformation method:{}'.format(_method))

    _item = Message(code_verifier=code_verifier, code_challenge_method=_method)
    _context.state.store_item(_item, 'pkce', request_args['state'])

    request_args.update(
        {
            "code_challenge": code_challenge,
            "code_challenge_method": _method
        })
    return request_args, {}


def add_code_verifier(request_args, service, **kwargs):
    """
    PKCE RFC 7636 support
    To be added as a post_construct method to an
    :py:class:`oidcrp.oidc.service.AccessToken` instance

    :param service: The service that uses this function
    :param request_args: Set of request arguments
    :return: updated set of request arguments
    """
    _state = request_args.get('state')
    if _state is None:
        _state = kwargs.get('state')
    _item = service.client_get("service_context").state.get_item(Message, 'pkce', _state)
    request_args.update({'code_verifier': _item['code_verifier']})
    return request_args


def put_state_in_post_args(request_args, **kwargs):
    state = get_state_parameter(request_args, kwargs)
    return request_args, {'state': state}


def add_support(service, code_challenge_length, code_challenge_method):
    """
    PKCE support can only be considered if this client can access authorization and
    access token services.

    :param service: Dictionary of services
    :param code_challenge_length:
    :param code_challenge_method:
    :return:
    """
    if "authorization" in service and "accesstoken" in service:
        _service = service["authorization"]
        _context = _service.client_get("service_context")
        _context.add_on['pkce'] = {
            "code_challenge_length": code_challenge_length,
            "code_challenge_method": code_challenge_method
        }

        _service.pre_construct.append(add_code_challenge)

        token_service = service['accesstoken']
        token_service.pre_construct.append(put_state_in_post_args)
        token_service.post_construct.append(add_code_verifier)
    else:
        logger.warning("PKCE support could NOT be added")
