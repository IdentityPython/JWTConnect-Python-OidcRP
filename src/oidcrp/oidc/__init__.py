import logging

try:
    from json import JSONDecodeError
except ImportError:  # Only works for >= 3.5
    _decode_err = ValueError
else:
    _decode_err = JSONDecodeError

from oidcservice.oidc import service
from oidcrp import oauth2

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

DEFAULT_SERVICES = {
    'ProviderInfoDiscovery': {},
    'Registration': {},
    'Authorization': {},
    'AccessToken': {},
    'RefreshAccessToken': {},
    'UserInfo': {}
}

# -----------------------------------------------------------------------------

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


class RP(oauth2.Client):
    def __init__(self, state_db, ca_certs=None, client_authn_factory=None,
                 keyjar=None, verify_ssl=True, config=None, client_cert=None,
                 httplib=None, services=None, service_factory=None):

        _srvs = services or DEFAULT_SERVICES
        service_factory = service_factory or service.factory
        oauth2.Client.__init__(self, state_db, ca_certs,
                               client_authn_factory=client_authn_factory,
                               keyjar=keyjar, verify_ssl=verify_ssl,
                               config=config, client_cert=client_cert,
                               httplib=httplib, services=_srvs,
                               service_factory=service_factory)

    def fetch_distributed_claims(self, userinfo, service, callback=None):
        """

        :param userinfo: A :py:class:`oidcmsg.message.Message` sub class instance
        :param service: Possibly an instance of the
            :py:class:`oidcservice.oidc.service.UserInfo` class
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
                        _uinfo = self.service_request(
                            service, spec["endpoint"], method='GET',
                            token=spec["access_token"])
                    else:
                        if callback:
                            _uinfo = self.service_request(
                                service, spec["endpoint"], method='GET',
                                token=callback(spec['endpoint']))
                        else:
                            _uinfo = self.service_request(
                                service, spec["endpoint"], method='GET')

                    claims = [value for value, src in
                              userinfo["_claim_names"].items() if src == csrc]

                    if set(claims) != set(list(_uinfo.keys())):
                        logger.warning(
                            "Claims from claim source doesn't match what's in "
                            "the userinfo")

                    for key, vals in _uinfo.items():
                        userinfo[key] = vals

        return userinfo
