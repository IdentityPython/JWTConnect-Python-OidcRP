import os

import pytest
from cryptojwt.key_jar import init_key_jar

from oidcrp.defaults import DEFAULT_OAUTH2_SERVICES
from oidcrp.oauth2 import Client

_dirname = os.path.dirname(os.path.abspath(__file__))

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, issuer_id='client_id')


class TestDPoPWithoutUserinfo:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id',
            'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']},
            'add_ons': {
                "ciba": {
                    "function": "oidcrp.oidc.add_on.ciba.add_support",
                    "kwargs": {
                        "signing_algorithms": ["ES256", "ES512"]
                    }
                }
            }
        }

        self.client = Client(keyjar=CLI_KEY, config=config, services=DEFAULT_OAUTH2_SERVICES)

        self.client.client_get("service_context").provider_info = {
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "dpop_signing_alg_values_supported": ["RS256", "ES256"]
        }
