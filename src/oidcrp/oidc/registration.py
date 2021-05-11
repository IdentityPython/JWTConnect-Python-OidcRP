import logging

from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage

from oidcrp.oidc.provider_info_discovery import add_redirect_uris
from oidcrp.service import Service

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

rt2gt = {
    'code': ['authorization_code'],
    'id_token': ['implicit'],
    'id_token token': ['implicit'],
    'code id_token': ['authorization_code', 'implicit'],
    'code token': ['authorization_code', 'implicit'],
    'code id_token token': ['authorization_code', 'implicit']
}


def response_types_to_grant_types(response_types):
    _res = set()

    for response_type in response_types:
        _rt = response_type.split(' ')
        _rt.sort()
        try:
            _gt = rt2gt[" ".join(_rt)]
        except KeyError:
            logger.warning(
                'No such response type combination: {}'.format(response_types))
        else:
            _res.update(set(_gt))

    return list(_res)


def add_request_uri(request_args=None, service=None, **kwargs):
    _context = service.client_get("service_context")
    if _context.requests_dir:
        _pi = _context.provider_info
        if _pi:
            _req = _pi.get('require_request_uri_registration', False)
            if _req is True:
                request_args['request_uris'] = _context.generate_request_uris(_context.requests_dir)

    return request_args, {}


def add_post_logout_redirect_uris(request_args=None, service=None, **kwargs):
    """

    :param request_args:
    :param service: pointer to the :py:class:`oidcrp.service.Service`
        instance that is running this function
    :param kwargs: parameters to the registration request
    :return:
    """

    if "post_logout_redirect_uris" not in request_args:
        _uris = service.client_get("service_context").register_args.get("post_logout_redirect_uris")
        if _uris:
            request_args["post_logout_redirect_uris"] = _uris

    return request_args, {}


def add_jwks_uri_or_jwks(request_args=None, service=None, **kwargs):
    if 'jwks_uri' in request_args:
        if 'jwks' in request_args:
            del request_args['jwks']  # only one of jwks_uri and jwks allowed
        return request_args, {}
    elif 'jwks' in request_args:
        return request_args, {}

    for attr in ['jwks_uri', 'jwks']:
        _val = getattr(service.client_get("service_context"), attr, 0)
        if _val:
            request_args[attr] = _val
            break
        else:
            try:
                _val = service.client_get("service_context").config[attr]
            except KeyError:
                pass
            else:
                request_args[attr] = _val
                break

    return request_args, {}


class Registration(Service):
    msg_type = oidc.RegistrationRequest
    response_cls = oidc.RegistrationResponse
    error_msg = ResponseMessage
    endpoint_name = 'registration_endpoint'
    synchronous = True
    service_name = 'registration'
    request_body_type = 'json'
    http_method = 'POST'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory,
                         conf=conf)
        self.pre_construct = [self.add_client_behaviour_preference,
                              add_redirect_uris, add_request_uri,
                              add_post_logout_redirect_uris,
                              add_jwks_uri_or_jwks]
        self.post_construct = [self.oidc_post_construct]

    def add_client_behaviour_preference(self, request_args=None, **kwargs):
        _context = self.client_get("service_context")
        for prop in self.msg_type.c_param.keys():
            if prop in request_args:
                continue

            try:
                request_args[prop] = _context.behaviour[prop]
            except KeyError:
                try:
                    request_args[
                        prop] = _context.client_preferences[prop]
                except KeyError:
                    pass
        return request_args, {}

    def oidc_post_construct(self, request_args=None, **kwargs):
        try:
            request_args['grant_types'] = response_types_to_grant_types(
                request_args['response_types'])
        except KeyError:
            pass

        # If a Client can use jwks_uri, it MUST NOT use jwks.
        if 'jwks_uri' in request_args and 'jwks' in request_args:
            del request_args['jwks']

        return request_args

    def update_service_context(self, resp, key='', **kwargs):
        if "token_endpoint_auth_method" not in resp:
            resp["token_endpoint_auth_method"] = "client_secret_basic"

        _context = self.client_get("service_context")
        _context.registration_response = resp
        _client_id = resp.get("client_id")
        if _client_id:
            _context.client_id = _client_id
            if _client_id not in _context.keyjar:
                _context.keyjar.import_jwks(
                    _context.keyjar.export_jwks(True, ''),
                    issuer_id=_client_id
                )
            _client_secret = resp.get("client_secret")
            if _client_secret:
                _context.client_secret = _client_secret
                _context.keyjar.add_symmetric('', _client_secret)
                _context.keyjar.add_symmetric(_client_id, _client_secret)
                try:
                    _context.client_secret_expires_at = resp["client_secret_expires_at"]
                except KeyError:
                    pass

        try:
            _context.registration_access_token = resp["registration_access_token"]
        except KeyError:
            pass
