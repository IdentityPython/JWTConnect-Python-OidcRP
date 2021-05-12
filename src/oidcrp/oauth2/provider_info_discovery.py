"""The service that talks to the OAuth2 provider info discovery endpoint."""
import logging

from cryptojwt.key_jar import KeyJar
from oidcmsg import oauth2
from oidcmsg.oauth2 import ResponseMessage

from oidcrp.defaults import OIDCONF_PATTERN
from oidcrp.exception import OidcServiceError
from oidcrp.service import Service

LOGGER = logging.getLogger(__name__)


class ProviderInfoDiscovery(Service):
    """The service that talks to the OAuth2 provider info discovery endpoint."""
    msg_type = oauth2.Message
    response_cls = oauth2.ASConfigurationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = 'provider_info'
    http_method = 'GET'

    def __init__(self, client_get, client_authn_factory=None, conf=None):
        Service.__init__(self, client_get,
                         client_authn_factory=client_authn_factory, conf=conf)

    def get_endpoint(self):
        """
        Find the issuer ID and from it construct the service endpoint

        :return: Service endpoint
        """
        try:
            _iss = self.client_get("service_context").issuer
        except AttributeError:
            _iss = self.endpoint

        if _iss.endswith('/'):
            return OIDCONF_PATTERN.format(_iss[:-1])

        return OIDCONF_PATTERN.format(_iss)

    def get_request_parameters(self, method="GET", **kwargs):
        """
        The Provider info discovery version of get_request_parameters()

        :param method:
        :param kwargs:
        :return:
        """
        return {'url': self.get_endpoint(), 'method': method}

    def _verify_issuer(self, resp, issuer):
        _pcr_issuer = resp["issuer"]
        if resp["issuer"].endswith("/"):
            if issuer.endswith("/"):
                _issuer = issuer
            else:
                _issuer = issuer + "/"
        else:
            if issuer.endswith("/"):
                _issuer = issuer[:-1]
            else:
                _issuer = issuer

        # In some cases we can live with the two URLs not being
        # the same. But this is an excepted that has to be explicit
        try:
            self.client_get("service_context").allow['issuer_mismatch']
        except KeyError:
            if _issuer != _pcr_issuer:
                raise OidcServiceError(
                    "provider info issuer mismatch '%s' != '%s'" % (
                        _issuer, _pcr_issuer))
        return _issuer

    def _set_endpoints(self, resp):
        """
        If there are services defined set the service endpoint to be
        the URLs specified in the provider information."""
        for key, val in resp.items():
            # All service endpoint parameters in the provider info has
            # a name ending in '_endpoint' so I can look specifically
            # for those
            if key.endswith("_endpoint"):
                _srv = self.client_get("service_by_endpoint_name", key)
                if _srv:
                    _srv.endpoint = val

    def _update_service_context(self, resp):
        """
        Deal with Provider Config Response. Based on the provider info
        response a set of parameters in different places needs to be set.

        :param resp: The provider info response
        :param service_context: Information collected/used by services
        """

        _context = self.client_get("service_context")
        # Verify that the issuer value received is the same as the
        # url that was used as service endpoint (without the .well-known part)
        if "issuer" in resp:
            _pcr_issuer = self._verify_issuer(resp, _context.issuer)
        else:  # No prior knowledge
            _pcr_issuer = _context.issuer

        _context.issuer = _pcr_issuer
        _context.provider_info = resp

        self._set_endpoints(resp)

        # If I already have a Key Jar then I'll add then provider keys to
        # that. Otherwise a new Key Jar is minted
        try:
            _keyjar = _context.keyjar
        except KeyError:
            _keyjar = KeyJar()

        # Load the keys. Note that this only means that the key specification
        # is loaded not necessarily that any keys are fetched.
        if 'jwks_uri' in resp:
            _keyjar.load_keys(_pcr_issuer, jwks_uri=resp['jwks_uri'])
        elif 'jwks' in resp:
            _keyjar.load_keys(_pcr_issuer, jwks=resp['jwks'])

        _context.keyjar = _keyjar

    def update_service_context(self, resp, **kwargs):
        return self._update_service_context(resp)
