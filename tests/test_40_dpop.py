import os

import pytest
from cryptojwt.jws.jws import factory
from cryptojwt.key_jar import init_key_jar

from oidcrp.client_auth import factory as ca_factory
from oidcrp.oauth2 import Client
from oidcrp.oauth2 import DEFAULT_OAUTH2_SERVICES
from oidcrp.oauth2.add_on import do_add_ons
from oidcrp.service import init_services
from oidcrp.service_context import ServiceContext

_dirname = os.path.dirname(os.path.abspath(__file__))

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, issuer_id='client_id')


class TestDPoP:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']},
            'add_ons': {
                "dpop": {
                    "function": "oidcrp.oauth2.add_on.dpop.add_support",
                    "kwargs": {
                        "signing_algorithms": ["ES256", "ES512"]
                    }
                }
            }
        }

        self.client = Client(keyjar=CLI_KEY, config=config, services=DEFAULT_OAUTH2_SERVICES)

        self.client.entity_get("service_context").provider_info= {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "dpop_signing_alg_values_supported": ["RS256", "ES256"]
        }

    def test_add_header(self):
        token_serv = self.client.entity_get("service","accesstoken")
        req_args = {
            "grant_type": "authorization_code",
            "code": "SplxlOBeZQQYbYS6WxSbIA",
            "redirect_uri": "https://client/example.com/cb"
        }
        headers = token_serv.get_headers(request=req_args, http_method="POST")
        assert headers
        assert "dpop" in headers

        # Now for the content of the DPoP proof
        _jws = factory(headers["dpop"])
        _payload = _jws.jwt.payload()
        assert _payload["htu"] == "https://example.com/token"
        assert _payload["htm"] == "POST"
        _header = _jws.jwt.headers
        assert "jwk" in _header
        assert _header["typ"] == "dpop+jwt"
        assert _header["alg"] == "ES256"
        assert _header["jwk"]["kty"] == "EC"
        assert _header["jwk"]["crv"] == "P-256"
