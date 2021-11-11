import json
import logging

from oidcrp.client_auth import BearerHeader
from oidcrp.oidc.registration import CALLBACK_URIS

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oidcrp import oauth2

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
#

DEFAULT_SERVICES = {
    "discovery": {
        'class': 'oidcrp.oidc.provider_info_discovery.ProviderInfoDiscovery'
    },
    'registration': {
        'class': 'oidcrp.oidc.registration.Registration'
    },
    'authorization': {
        'class': 'oidcrp.oidc.authorization.Authorization'
    },
    'access_token': {
        'class': 'oidcrp.oidc.access_token.AccessToken'
    },
    'refresh_access_token': {
        'class': 'oidcrp.oidc.refresh_access_token.RefreshAccessToken'
    },
    'userinfo': {
        'class': 'oidcrp.oidc.userinfo.UserInfo'
    },
    'end_session': {
        'class': 'oidcrp.oidc.end_session.EndSession'
    }
}

WF_URL = "https://{}/.well-known/webfinger"
OIC_ISSUER = "http://openid.net/specs/connect/1.0/issuer"

IDT2REG = {
    'sigalg': 'id_token_signed_response_alg',
    'encalg': 'id_token_encrypted_response_alg',
    'encenc': 'id_token_encrypted_response_enc'
}

ENDPOINT2SERVICE = {
    'authorization': ['authorization'],
    'token': ['accesstoken', 'refresh_token'],
    'userinfo': ['userinfo'],
    'registration': ['registration'],
    'end_sesssion': ['end_session']
}

# This should probably be part of the configuration
MAX_AUTHENTICATION_AGE = 86400

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
    'grant_types': 'grant_types_supported'
}

PROVIDER2PREFERENCE = dict([(v, k) for k, v in PREFERENCE2PROVIDER.items()])

PROVIDER_DEFAULT = {
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
}


class FetchException(Exception):
    pass


class RP(oauth2.Client):
    def __init__(self, client_authn_factory=None,
                 keyjar=None, verify_ssl=True, config=None,
                 httplib=None, services=None, httpc_params=None):

        _srvs = services or DEFAULT_SERVICES

        oauth2.Client.__init__(self, client_authn_factory=client_authn_factory,
                               keyjar=keyjar, verify_ssl=verify_ssl, config=config,
                               httplib=httplib, services=_srvs, httpc_params=httpc_params)

        _context = self.get_service_context()
        if _context.callback is None:
            _context.callback = {}

        for _cb in CALLBACK_URIS:
            _uri = config.get(_cb)
            if _uri:
                _context.callback[_cb] = _uri

    def fetch_distributed_claims(self, userinfo, callback=None):
        """

        :param userinfo: A :py:class:`oidcmsg.message.Message` sub class
            instance
        :param callback: A function that can be used to fetch things
        :return: Updated userinfo instance
        """
        try:
            _csrc = userinfo["_claim_sources"]
        except KeyError:
            pass
        else:
            for csrc, spec in _csrc.items():
                if "endpoint" in spec:
                    if "access_token" in spec:
                        cauth = BearerHeader()
                        httpc_params = cauth.construct(
                            service=self.client_get("service", 'userinfo'),
                            access_token=spec['access_token'])
                        _resp = self.http.send(spec["endpoint"], 'GET',
                                               **httpc_params)
                    else:
                        if callback:
                            token = callback(spec['endpoint'])
                            cauth = BearerHeader()
                            httpc_params = cauth.construct(
                                service=self.client_get("service",'userinfo'),
                                access_token=token)
                            _resp = self.http.send(
                                spec["endpoint"], 'GET', **httpc_params)
                        else:
                            _resp = self.http.send(spec["endpoint"], 'GET')

                    if _resp.status_code == 200:
                        _uinfo = json.loads(_resp.text)
                    else:  # There shouldn't be any redirect
                        raise FetchException(
                            'HTTP error {}: {}'.format(_resp.status_code,
                                                       _resp.reason))

                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]

                    if set(claims) != set(_uinfo.keys()):
                        logger.warning(
                            "Claims from claim source doesn't match what's in "
                            "the userinfo")

                    # only add those I expected
                    for key in claims:
                        userinfo[key] = _uinfo[key]

        return userinfo
