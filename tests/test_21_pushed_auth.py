import json
import os

from cryptojwt.key_jar import init_key_jar
import pytest
import responses

from oidcrp.oauth2 import Client
from oidcrp.oauth2 import DEFAULT_OAUTH2_SERVICES

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

KEYSPEC = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYSPEC, issuer_id='')


class TestPushedAuth:
    @pytest.fixture(autouse=True)
    def create_client(self):
        config = {
            'client_id': 'client_id', 'client_secret': 'a longesh password',
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'behaviour': {'response_types': ['code']},
            'add_ons': {
                "pushed_authorization": {
                    "function":
                        "oidcrp.oauth2.add_on.pushed_authorization.add_support",
                    "kwargs": {
                        "body_format": "jws",
                        "signing_algorithm": "RS256",
                        "http_client": None,
                        "merge_rule": "lax"
                    }
                }
            }
        }
        self.entity = Client(keyjar=CLI_KEY, config=config, services=DEFAULT_OAUTH2_SERVICES)

        self.entity.client_get("service_context").provider_info = {
            "pushed_authorization_request_endpoint": "https://as.example.com/push"
        }

    def test_authorization(self):
        auth_service = self.entity.client_get("service","authorization")
        req_args = {'foo': 'bar', "response_type": "code"}
        with responses.RequestsMock() as rsps:
            _resp = {
                "request_uri": "urn:example:bwc4JK-ESC0w8acc191e-Y1LTC2",
                "expires_in": 3600
            }
            rsps.add("GET",
                     auth_service.client_get("service_context").provider_info[
                         "pushed_authorization_request_endpoint"],
                     body=json.dumps(_resp), status=200)

            _req = auth_service.construct(request_args=req_args, state='state')

        assert set(_req.keys()) == {"request_uri", "response_type", "client_id"}
