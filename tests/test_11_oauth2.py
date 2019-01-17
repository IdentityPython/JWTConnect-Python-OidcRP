import os
import pytest
import sys
import time

from cherrypy import HTTPError

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle

from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import RefreshAccessTokenRequest
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import IdToken
from oidcmsg.time_util import utc_time_sans_frac
from oidcservice.exception import ParseError

from oidcrp.oauth2 import Client

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


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        return self.db[item]


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = ''


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "http://example.com/redirect"
        conf = {
            'redirect_uris': ['https://example.com/cli/authz_cb'],
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop'
        }
        self.client = Client(DB(), config=conf)

    def test_construct_authorization_request(self):
        req_args = {'state': 'ABCDE',
                    'redirect_uri': 'https://example.com/auth_cb',
                    'response_type': ['code']}

        self.client.session_interface.create_state('issuer',key='ABCDE')
        msg = self.client.service['authorization'].construct(
            request_args=req_args)
        assert isinstance(msg, AuthorizationRequest)
        assert msg['client_id'] == 'client_1'
        assert msg['redirect_uri'] == 'https://example.com/auth_cb'

    def test_construct_accesstoken_request(self):
        # Bind access code to state
        req_args = {}

        self.client.session_interface.create_state('issuer', 'ABCDE')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='ABCDE'
        )

        self.client.session_interface.store_item(auth_request, 'auth_request',
                                                 'ABCDE')

        auth_response = AuthorizationResponse(code='access_code')

        self.client.session_interface.store_item(auth_response,
                                                 'auth_response', 'ABCDE')

        msg = self.client.service['accesstoken'].construct(
            request_args=req_args, state='ABCDE')

        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {'client_id': 'client_1',
                                 'code': 'access_code',
                                 'client_secret': 'abcdefghijklmnop',
                                 'grant_type': 'authorization_code',
                                 'redirect_uri':
                                     'https://example.com/cli/authz_cb',
                                 'state': 'ABCDE'}

    def test_construct_refresh_token_request(self):

        self.client.session_interface.create_state('issuer', 'ABCDE')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state='state'
        )

        self.client.session_interface.store_item(auth_request, 'auth_request',
                                                 'ABCDE')

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
            'refresh_token': 'refresh_with_me'}

    def test_error_response(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(400, err.to_urlencoded())
        resp = self.client.parse_request_response(
            self.client.service['authorization'], http_resp)

        assert resp['error'] == 'Illegal'
        assert resp['status_code'] == 400

    def test_error_response_500(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(500, err.to_urlencoded())
        with pytest.raises(ParseError):
            self.client.parse_request_response(
                self.client.service['authorization'], http_resp)

    def test_error_response_2(self):
        err = ResponseMessage(error='Illegal')
        http_resp = MockResponse(
            400, err.to_json(),
            headers={'content-type': 'application/x-www-form-urlencoded'})

        with pytest.raises(HTTPError):
            self.client.parse_request_response(
                self.client.service['authorization'], http_resp)

