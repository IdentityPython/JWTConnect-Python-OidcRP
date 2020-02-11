import json
import os
import sys
import time

import pytest
from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import RefreshAccessTokenRequest
from oidcmsg.oidc import IdToken
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.time_util import utc_time_sans_frac

from oidcrp.oidc import RP

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oidc.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


def access_token_callback(endpoint):
    if endpoint:
        return 'access_token'


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        return self.db[item]


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop',
        }
        self.client = RP(DB(), config=conf)

    def test_construct_authorization_request(self):
        req_args = {
            'state': 'ABCDE',
            'redirect_uri': 'https://example.com/auth_cb',
            'response_type': ['code']
        }

        self.client.session_interface.create_state('issuer', 'ABCDE')

        msg = self.client.service['authorization'].construct(
            request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['redirect_uri'] == 'https://example.com/auth_cb'

    def test_construct_accesstoken_request(self):
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='ABCDE'
        )

        self.client.session_interface.store_item(auth_request,
                                                 'auth_request', 'ABCDE')

        auth_response = AuthorizationResponse(code='access_code')

        self.client.session_interface.store_item(auth_response,
                                                 'auth_response', 'ABCDE')

        # Bind access code to state
        req_args = {}
        msg = self.client.service['accesstoken'].construct(
            request_args=req_args, state='ABCDE')
        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {
            'client_id': 'client_1', 'code': 'access_code',
            'client_secret': 'abcdefghijklmnop',
            'grant_type': 'authorization_code',
            'redirect_uri': 'https://example.com/cli/authz_cb',
            'state': 'ABCDE'
        }

    def test_construct_refresh_token_request(self):
        self.client.session_interface.create_state('issuer', 'ABCDE')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )

        self.client.session_interface.store_item(auth_request,
                                                 'auth_request', 'ABCDE')

        auth_response = AuthorizationResponse(code='access_code')
        self.client.session_interface.store_item(auth_response,
                                                 'auth_response', 'ABCDE')

        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access")
        self.client.session_interface.store_item(token_response,
                                                 'token_response', 'ABCDE')

        req_args = {}
        msg = self.client.service['refresh_token'].construct(
            request_args=req_args, state='ABCDE')
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop',
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh_with_me'
        }

    def test_do_userinfo_request_init(self):
        self.client.session_interface.create_state('issuer', 'ABCDE')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )

        self.client.session_interface.store_item(auth_request,
                                                 'auth_request', 'ABCDE')

        auth_response = AuthorizationResponse(code='access_code')
        self.client.session_interface.store_item(auth_response,
                                                 'auth_response', 'ABCDE')

        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access")
        self.client.session_interface.store_item(token_response,
                                                 'token_response', 'ABCDE')

        _srv = self.client.service['userinfo']
        _srv.endpoint = "https://example.com/userinfo"
        _info = _srv.get_request_parameters(state='ABCDE')
        assert _info
        assert _info['headers'] == {'Authorization': 'Bearer access'}
        assert _info['url'] == 'https://example.com/userinfo'

    def test_fetch_distributed_claims_1(self, httpserver):
        _url = httpserver.url

        # split the example in 5.6.2.2 into two
        uinfo = OpenIDSchema(**{
            "sub": 'jane_doe',
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com",
            "birthdate": "0000-03-22",
            "eye_color": "blue",
            "_claim_names": {
                "payment_info": "src1",
                "shipping_address": "src1",
            },
            "_claim_sources": {
                "src1": {
                    "endpoint": _url
                }
            }
        })

        # Wrong set of claims. Actually extra claim
        httpserver.serve_content(json.dumps({
            "shipping_address": {
                "street_address": "1234 Hollywood Blvd.",
                "locality": "Los Angeles",
                "region": "CA",
                "postal_code": "90210",
                "country": "US"
            },
            "payment_info": "Some_Card 1234 5678 9012 3456",
            "phone_number": "+1 (310) 123-4567"
        }))

        res = self.client.fetch_distributed_claims(uinfo)

        assert 'payment_info' in res
        assert 'shipping_address' in res
        assert 'phone_number' not in res

    def test_fetch_distributed_claims_2(self, httpserver):
        _url = httpserver.url

        uinfo = OpenIDSchema(**{
            "sub": 'jane_doe',
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com",
            "birthdate": "0000-03-22",
            "eye_color": "blue",
            "_claim_names": {
                "credit_score": "src2"
            },
            "_claim_sources": {
                "src2": {
                    "endpoint": _url,
                    "access_token": "ksj3n283dke"
                }
            }
        })

        httpserver.serve_content(json.dumps({
            "credit_score": 650
        }))

        res = self.client.fetch_distributed_claims(uinfo)

        assert 'credit_score' in res

    def test_fetch_distributed_claims_3(self, httpserver):
        _url = httpserver.url

        uinfo = OpenIDSchema(**{
            "sub": 'jane_doe',
            "name": "Jane Doe",
            "given_name": "Jane",
            "family_name": "Doe",
            "email": "janedoe@example.com",
            "birthdate": "0000-03-22",
            "eye_color": "blue",
            "_claim_names": {
                "credit_score": "src2"
            },
            "_claim_sources": {
                "src2": {
                    "endpoint": _url,
                }
            }
        })

        httpserver.serve_content(json.dumps({
            "credit_score": 650
        }))

        res = self.client.fetch_distributed_claims(
            uinfo, callback=access_token_callback)

        assert 'credit_score' in res
