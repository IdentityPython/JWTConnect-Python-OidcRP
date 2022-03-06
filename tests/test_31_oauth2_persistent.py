import os
import sys
import time

from cryptojwt.jwk.rsa import import_private_rsa_key_from_file
from cryptojwt.key_bundle import KeyBundle
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import RefreshAccessTokenRequest
from oidcmsg.oidc import IdToken
from oidcmsg.time_util import utc_time_sans_frac

from oidcrp.oauth2 import Client

sys.path.insert(0, '.')

_dirname = os.path.dirname(os.path.abspath(__file__))
BASE_PATH = os.path.join(_dirname, "data", "keys")

_key = import_private_rsa_key_from_file(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"priv_key": _key, "kty": "RSA", "use": "sig"})

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oidc.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())

CONF = {
    'issuer': 'https://op.example.com',
    'redirect_uris': ['https://example.com/cli/authz_cb'],
    'client_id': CLIENT_ID,
    'client_secret': 'abcdefghijklmnop'
}


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = ''


class TestClient(object):
    def test_construct_accesstoken_request(self):
        # Client 1 starts the chain of event
        client_1 = Client(config=CONF)
        _context_1 = client_1.client_get("service_context")
        _state = _context_1.state.create_state('issuer')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state=_state
        )

        _context_1.state.store_item(auth_request, 'auth_request', _state)

        # Client 2 carries on
        client_2 = Client(config=CONF)
        _state_dump = _context_1.dump()

        _context2 = client_2.client_get("service_context")
        _context2.load(_state_dump)

        auth_response = AuthorizationResponse(code='access_code')
        _context2.state.store_item(auth_response, 'auth_response', _state)

        msg = client_2.client_get("service", 'accesstoken').construct(request_args={}, state=_state)

        assert isinstance(msg, AccessTokenRequest)
        assert msg.to_dict() == {
            'client_id': 'client_1',
            'code': 'access_code',
            'client_secret': 'abcdefghijklmnop',
            'grant_type': 'authorization_code',
            'redirect_uri':
                'https://example.com/cli/authz_cb',
            'state': _state
        }

    def test_construct_refresh_token_request(self):
        # Client 1 starts the chain event
        client_1 = Client(config=CONF)
        _state = client_1.client_get("service_context").state.create_state('issuer')

        auth_request = AuthorizationRequest(
            redirect_uri='https://example.com/cli/authz_cb',
            state=_state
        )

        client_1.client_get("service_context").state.store_item(auth_request, 'auth_request',
                                                                _state)

        # Client 2 carries on
        client_2 = Client(config=CONF)
        _state_dump = client_1.client_get("service_context").dump()
        client_2.client_get("service_context").load(_state_dump)

        auth_response = AuthorizationResponse(code='access_code')
        client_2.client_get("service_context").state.store_item(auth_response, 'auth_response',
                                                                _state)

        token_response = AccessTokenResponse(refresh_token="refresh_with_me",
                                             access_token="access")

        client_2.client_get("service_context").state.store_item(token_response, 'token_response',
                                                                _state)

        # Next up is Client 1
        _state_dump = client_2.client_get("service_context").dump()
        client_1.client_get("service_context").load(_state_dump)

        req_args = {}
        msg = client_1.client_get("service", 'refresh_token').construct(request_args=req_args,
                                                                        state=_state)
        assert isinstance(msg, RefreshAccessTokenRequest)
        assert msg.to_dict() == {
            'client_id': 'client_1',
            'client_secret': 'abcdefghijklmnop',
            'grant_type': 'refresh_token',
            'refresh_token': 'refresh_with_me'
        }
