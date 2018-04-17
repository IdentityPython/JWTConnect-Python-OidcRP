import os
import pytest
import sys
import time

from cryptojwt.jwk import rsa_load

from oidcmsg.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenRequest, AuthorizationResponse
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import RefreshAccessTokenRequest
from oidcmsg.oidc import IdToken
from oidcmsg.time_util import utc_time_sans_frac

from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.state_interface import State

from oidcrp.oidc import RP

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oidc.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


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
        self.client.state_db.set('ABCDE', State(iss='issuer').to_json())

    def test_construct_authorization_request(self):
        req_args = {'state': 'ABCDE',
                    'redirect_uri': 'https://example.com/auth_cb',
                    'response_type': ['code']}
        msg = self.client.service['authorization'].construct(
            request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['redirect_uri'] == 'https://example.com/auth_cb'

    def test_construct_accesstoken_request(self):
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )
        auth_response = AuthorizationResponse(code='access_code')
        _state = State(auth_response=auth_response.to_json(),
                       auth_request=auth_request.to_json())
        self.client.state_db.set('ABCDE', _state.to_json())
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
            'state': 'state'}

    def test_construct_refresh_token_request(self):
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )
        auth_response = AuthorizationResponse(code='access_code')
        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access")
        _state = State(auth_response=auth_response.to_json(),
                       auth_request=auth_request.to_json(),
                       token_response=token_response.to_json())

        self.client.state_db.set('ABCDE', _state.to_json())

        req_args = {}
        msg = self.client.service['refresh_token'].construct(
            request_args=req_args, state='ABCDE')
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'refresh_token',
                                 'refresh_token': 'refresh_with_me'}

    def test_do_userinfo_request_init(self):
        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )
        auth_response = AuthorizationResponse(code='access_code')
        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access")
        _state = State(auth_response=auth_response.to_json(),
                       auth_request=auth_request.to_json(),
                       token_response=token_response.to_json())

        self.client.state_db.set('ABCDE', _state.to_json())

        _srv = self.client.service['userinfo']
        _srv.endpoint = "https://example.com/userinfo"
        _info = _srv.get_request_parameters(state='ABCDE')
        assert _info
        assert _info['headers'] == {'Authorization': 'Bearer access'}
        assert _info['url'] == 'https://example.com/userinfo'
