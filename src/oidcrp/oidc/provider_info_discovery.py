import logging

from oidcmsg import oidc
from oidcmsg.oauth2 import ResponseMessage

from oidcrp.exception import ConfigurationError
from oidcrp.oauth2 import provider_info_discovery

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

PREFERENCE2PROVIDER = {
    # "require_signed_request_object": "request_object_algs_supported",
    "request_object_signing_alg": "request_object_signing_alg_values_supported",
    "request_object_encryption_alg":
        "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc":
        "request_object_encryption_enc_values_supported",
    "userinfo_signed_response_alg": "userinfo_signing_alg_values_supported",
    "userinfo_encrypted_response_alg":
        "userinfo_encryption_alg_values_supported",
    "userinfo_encrypted_response_enc":
        "userinfo_encryption_enc_values_supported",
    "id_token_signed_response_alg": "id_token_signing_alg_values_supported",
    "id_token_encrypted_response_alg":
        "id_token_encryption_alg_values_supported",
    "id_token_encrypted_response_enc":
        "id_token_encryption_enc_values_supported",
    "default_acr_values": "acr_values_supported",
    "subject_type": "subject_types_supported",
    "token_endpoint_auth_method": "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg":
        "token_endpoint_auth_signing_alg_values_supported",
    "response_types": "response_types_supported",
    'grant_types': 'grant_types_supported',
    'scope': 'scopes_supported'
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


def add_redirect_uris(request_args, service=None, **kwargs):
    """
    Add redirect_uris to the request arguments.

    :param request_args: Incomming request arguments
    :param service: A link to the service
    :param kwargs: Possible extra keyword arguments
    :return: A possibly augmented set of request arguments.
    """
    _context = service.client_get("service_context")
    if "redirect_uris" not in request_args:
        # Callbacks is a dictionary with callback type 'code', 'implicit',
        # 'form_post' as keys.
        _cbs = _context.callback
        if _cbs:
            # Filter out local additions.
            _uris = [v for k, v in _cbs.items() if not k.startswith('__')]
            request_args['redirect_uris'] = _uris
        else:
            request_args['redirect_uris'] = _context.redirect_uris

    return request_args, {}


class ProviderInfoDiscovery(provider_info_discovery.ProviderInfoDiscovery):
    msg_type = oidc.Message
    response_cls = oidc.ProviderConfigurationResponse
    error_msg = ResponseMessage

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        provider_info_discovery.ProviderInfoDiscovery.__init__(
            self, client_get, client_authn_factory=client_authn_factory,
            conf=conf)

    def update_service_context(self, resp, **kwargs):
        _context = self.client_get("service_context")
        self._update_service_context(resp)
        self.match_preferences(resp, _context.issuer)
        if 'pre_load_keys' in self.conf and self.conf['pre_load_keys']:
            _jwks = _context.keyjar.export_jwks_as_json(
                issuer=resp['issuer'])
            logger.info(
                'Preloaded keys for {}: {}'.format(resp['issuer'], _jwks))

    def match_preferences(self, pcr=None, issuer=None):
        """
        Match the clients preferences against what the provider can do.
        This is to prepare for later client registration and or what
        functionality the client actually will use.
        In the client configuration the client preferences are expressed.
        These are then compared with the Provider Configuration information.
        If the Provider has left some claims out, defaults specified in the
        standard will be used.

        :param pcr: Provider configuration response if available
        :param issuer: The issuer identifier
        """
        _context = self.client_get("service_context")
        if not pcr:
            pcr = _context.provider_info

        regreq = oidc.RegistrationRequest

        _behaviour = _context.behaviour

        for _pref, _prov in PREFERENCE2PROVIDER.items():
            try:
                vals = _context.client_preferences[_pref]
            except KeyError:
                continue

            try:
                _pvals = pcr[_prov]
            except KeyError:
                try:
                    # If the provider have not specified use what the
                    # standard says is mandatory if at all.
                    _pvals = PROVIDER_DEFAULT[_pref]
                except KeyError:
                    logger.info(
                        'No info from provider on {} and no default'.format(
                            _pref))
                    _pvals = vals

            if isinstance(vals, str):
                if vals in _pvals:
                    _behaviour[_pref] = vals
            else:
                try:
                    vtyp = regreq.c_param[_pref]
                except KeyError:
                    # Allow non standard claims
                    if isinstance(vals, list):
                        _behaviour[_pref] = [v for v in vals if v in _pvals]
                    elif vals in _pvals:
                        _behaviour[_pref] = vals
                else:
                    if isinstance(vtyp[0], list):
                        _behaviour[_pref] = []
                        for val in vals:
                            if val in _pvals:
                                _behaviour[_pref].append(
                                    val)
                    else:
                        for val in vals:
                            if val in _pvals:
                                _behaviour[_pref] = val
                                break

            if _pref not in _behaviour:
                raise ConfigurationError("OP couldn't match preference:%s" % _pref, pcr)

        for key, val in _context.client_preferences.items():
            if key in _behaviour:
                continue

            try:
                vtyp = regreq.c_param[key]
                if isinstance(vtyp[0], list):
                    pass
                elif isinstance(val, list) and not isinstance(val, str):
                    val = val[0]
            except KeyError:
                pass
            if key not in PREFERENCE2PROVIDER:
                _behaviour[key] = val

        _context.behaviour= _behaviour
        logger.debug('service_context behaviour: {}'.format(_behaviour))
