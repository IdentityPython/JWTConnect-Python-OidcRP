import hashlib
import logging
from typing import List
from typing import Optional

from cryptojwt.utils import as_bytes
from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage

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


def create_callbacks(issuer: str,
                     hash_seed: str,
                     base_url: str,
                     code: Optional[bool] = False,
                     implicit: Optional[bool] = False,
                     form_post: Optional[bool] = False,
                     request_uris: Optional[bool] = False,
                     backchannel_logout_uri: Optional[bool] = False,
                     frontchannel_logout_uri: Optional[bool] = False):
    """
    To mitigate some security issues the redirect_uris should be OP/AS
    specific. This method creates a set of redirect_uris unique to the
    OP/AS.

    :param frontchannel_logout_uri: Whether a front-channel logout uri should be constructed
    :param backchannel_logout_uri: Whether a back-channel logout uri should be constructed
    :param request_uri: Whether a request_uri should be constructed
    :param issuer: Issuer ID
    :return: A set of redirect_uris
    """
    _hash = hashlib.sha256()
    _hash.update(hash_seed)
    _hash.update(as_bytes(issuer))
    _hex = _hash.hexdigest()

    res = {'__hex': _hex}

    if code:
        res['code'] = f"{base_url}/authz_cb/{_hex}"

    if implicit:
        res['implicit'] = f"{base_url}/authz_im_cb/{_hex}"

    if form_post:
        res['form_post'] = f"{base_url}/authz_fp_cb/{_hex}"

    if request_uris:
        res["request_uris"] = f"{base_url}/req_uri/{_hex}"

    if backchannel_logout_uri or frontchannel_logout_uri:
        res["post_logout_redirect_uris"] = [f"{base_url}/session_logout/{_hex}"]

    if backchannel_logout_uri:
        res["backchannel_logout_uri"] = f"{base_url}/bc_logout/{_hex}"

    if frontchannel_logout_uri:
        res["frontchannel_logout_uri"] = f"{base_url}/fc_logout/{_hex}"

    logger.debug(f"Created callback URIs: {res}")
    return res


def _cmp(a, b):
    if b is None:  # Don't care about the value as long as there is one
        return True
    elif isinstance(a, str) and a == b:
        return True
    elif isinstance(a, list) and b in a:
        return True

    return a == b


def _in_config_or_client_preferences(config, attr, val):
    _val = config.get("client_preferences", {}).get(attr)
    if _cmp(_val, val):
        return True
    _val = config.get(attr)
    return _cmp(_val, val)


def add_callbacks(context, ignore: Optional[List[str]] = None):
    if ignore is None:
        ignore = []
    _iss = context.get('issuer')

    _uris = {}

    _pi = context.get('provider_info')
    _cp = context.config.get("client_preferences")

    if "redirect_uris" not in ignore:
        # code and/or implicit
        if _in_config_or_client_preferences(context.config, "response_types", "code"):
            _uris['code'] = True
        for rt in ["id_token", "id_token token", "code id_token token", "code idtoken",
                   "code token"]:
            if _in_config_or_client_preferences(context.config, "response_types", rt):
                _uris["implicit"] = True
                break

    if "form_post" not in ignore:
        if _in_config_or_client_preferences(context.config, "form_post_usable", True):
            _uris["form_post"] = True

    if "request_uris" not in ignore:
        if 'require_request_uri_registration' in _pi and _in_config_or_client_preferences(
                context.config, "request_uri_usable", True):
            _uris['request_uris'] = True

    if "frontchannel_logout_uri" not in ignore:
        if 'frontchannel_logout_supported' in _pi and _in_config_or_client_preferences(
                context.config, "frontchannel_logout_usable", True):
            _uris["frontchannel_logout_uri"] = True

    if "backchannel_logout_uri" not in ignore:
        if 'backchannel_logout_supported' in _pi and _in_config_or_client_preferences(
                context.config, "backchannel_logout_usable", True):
            _uris["backchannel_logout_uri"] = True

    callbacks = create_callbacks(_iss,
                                 hash_seed=context.get('hash_seed'),
                                 base_url=context.get("base_url"),
                                 **_uris)
    context.hash2issuer[callbacks['__hex']] = _iss

    if "redirect_uris" not in ignore:
        _redirect_uris = [v for k, v in callbacks.items() if k in ["code", "implicit", "form_post"]]
        callbacks["redirect_uris"] = _redirect_uris
    context.set('callback', callbacks)


CALLBACK_URIS = ["post_logout_redirect_uris", "backchannel_logout_uri", "frontchannel_logout_uri",
                 "request_uris", 'redirect_uris']


def add_callback_uris(request_args=None, service=None, **kwargs):
    """

    :param request_args:
    :param service: pointer to the :py:class:`oidcrp.service.Service`
        instance that is running this function
    :param kwargs: parameters to the registration request
    :return:
    """

    _context = service.client_get("service_context")
    _ignore = [k for k in list(request_args.keys()) if k in CALLBACK_URIS]
    add_callbacks(_context, ignore=_ignore)
    for _key in CALLBACK_URIS:
        _req_val = request_args.get(_key)
        if not _req_val:
            _uri = _context.register_args.get(_key)
            if not _uri:
                _uri = _context.callback.get(_key)
            if _uri:
                request_args[_key] = _uri

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
                              #add_redirect_uris,
                              add_callback_uris,
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
