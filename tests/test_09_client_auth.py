import base64
import os
from urllib.parse import quote_plus

from cryptojwt.exception import MissingKey
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.jwt import JWT
from cryptojwt.key_bundle import KeyBundle
from cryptojwt.key_jar import KeyJar
from oidcmsg.message import Message
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import AccessTokenResponse
from oidcmsg.oauth2 import AuthorizationRequest
from oidcmsg.oauth2 import AuthorizationResponse
from oidcmsg.oauth2 import CCAccessTokenRequest
from oidcmsg.oauth2 import ResourceRequest
import pytest

from oidcrp.client_auth import AuthnFailure
from oidcrp.client_auth import BearerBody
from oidcrp.client_auth import BearerHeader
from oidcrp.client_auth import ClientSecretBasic
from oidcrp.client_auth import ClientSecretJWT
from oidcrp.client_auth import ClientSecretPost
from oidcrp.client_auth import PrivateKeyJWT
from oidcrp.client_auth import assertion_jwt
from oidcrp.client_auth import bearer_auth
from oidcrp.client_auth import valid_service_context
from oidcrp.defaults import JWT_BEARER
from oidcrp.entity import Entity

BASE_PATH = os.path.abspath(os.path.dirname(__file__))
CLIENT_ID = "A"

CLIENT_CONF = {'issuer': 'https://example.com/as',
               'redirect_uris': ['https://example.com/cli/authz_cb'],
               'client_secret': 'white boarding pass',
               'client_id': CLIENT_ID}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def entity():
    return Entity(config=CLIENT_CONF)


def test_quote():
    csb = ClientSecretBasic()
    http_args = csb.construct(
        Message(),
        password='MKEM/A7Pkn7JuU0LAcxyHVKvwdczsugaPU0BieLb4CbQAgQj+ypcanFOCb0/FA5h',
        user='796d8fae-a42f-4e4f-ab25-d6205b6d4fa2')

    assert http_args['headers'][
               'Authorization'] == 'Basic ' \
                                   'Nzk2ZDhmYWUtYTQyZi00ZTRmLWFiMjUtZDYyMDViNmQ0ZmEyOk1LRU0lMkZBN1BrbjdKdVUwTEFjeHlIVkt2d2RjenN1Z2FQVTBCaWVMYjRDYlFBZ1FqJTJCeXBjYW5GT0NiMCUyRkZBNWg='


class TestClientSecretBasic(object):
    def test_construct(self, entity):
        _token_service = entity.client_get("service", "accesstoken")
        request = _token_service.construct(redirect_uri="http://example.com",
                                                     state='ABCDE')

        csb = ClientSecretBasic()
        http_args = csb.construct(request, _token_service)

        credentials = "{}:{}".format(quote_plus('A'), quote_plus('white boarding pass'))

        assert http_args == {"headers": {"Authorization": "Basic {}".format(
            base64.urlsafe_b64encode(credentials.encode("utf-8")).decode(
                "utf-8"))}}

    def test_does_not_remove_padding(self):
        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")

    def test_construct_cc(self):
        """CC == Client Credentials, the 4th OAuth2 flow"""
        request = CCAccessTokenRequest(grant_type="client_credentials")

        csb = ClientSecretBasic()
        http_args = csb.construct(request, user="service1", password="secret")

        assert http_args["headers"]["Authorization"].startswith('Basic ')


class TestBearerHeader(object):
    def test_construct(self, entity):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        http_args = bh.construct(request,
                                 service=entity.client_get("service", "accesstoken"))

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self, entity):
        request = ResourceRequest(access_token="Sesame")
        bh = BearerHeader()
        # Any HTTP args should just be passed on
        http_args = bh.construct(request,
                                 service=entity.client_get("service", "accesstoken"),
                                 http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers_in_http_args(self, entity):
        request = ResourceRequest(access_token="Sesame")

        bh = BearerHeader()
        http_args = bh.construct(request,
                                 service=entity.client_get("service", "accesstoken"),
                                 http_args={"headers": {"x-foo": "bar"}})

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self, entity):
        bh = BearerHeader()
        request = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(request,
                                 service=entity.client_get("service", "accesstoken"))

        assert "access_token" not in request
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, entity):
        authz_service = entity.client_get("service", 'authorization')
        srv_cntx = authz_service.client_get("service_context")
        _state = srv_cntx.state.create_state('Issuer')
        req = AuthorizationRequest(state=_state, response_type='code',
                                   redirect_uri='https://example.com',
                                   scope=['openid'])
        srv_cntx.state.store_item(req, 'auth_request', _state)

        # Add a state and bind a code to it
        resp1 = AuthorizationResponse(code="auth_grant", state=_state)
        response = authz_service.parse_response(
            resp1.to_urlencoded(), "urlencoded")
        authz_service.update_service_context(response, key=_state)

        # based on state find the code and then get an access token
        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state=_state)
        _token_service = entity.client_get("service", 'accesstoken')
        response = _token_service.parse_response(
            resp2.to_urlencoded(), "urlencoded")

        _token_service.update_service_context(response, key=_state)

        # and finally use the access token, bound to a state, to
        # construct the authorization header
        http_args = BearerHeader().construct(
            ResourceRequest(), _token_service, key=_state)
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):
    def test_construct(self, entity):
        _token_service = entity.client_get("service", 'accesstoken')
        request = ResourceRequest(access_token="Sesame")
        http_args = BearerBody().construct(request, service=_token_service)

        assert request["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, entity):
        _auth_service = entity.client_get("service", 'authorization')
        _cntx = _auth_service.client_get("service_context")
        _key = _cntx.state.create_state(iss='Issuer')

        resp = AuthorizationResponse(code="code", state=_key)
        _cntx.state.store_item(resp, 'auth_response', _key)

        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  scope=["inner", "outer"])
        _cntx.state.store_item(atr, 'token_response', _key)

        request = ResourceRequest()
        http_args = BearerBody().construct(request, service=_auth_service, key=_key)
        assert request["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, entity):
        authz_service = entity.client_get("service", 'authorization')
        _cntx = authz_service.client_get("service_context")

        _key = _cntx.state.create_state(iss='Issuer')
        resp1 = AuthorizationResponse(code="auth_grant", state=_key)
        response = authz_service.parse_response(resp1.to_urlencoded(),
                                                "urlencoded")
        authz_service.update_service_context(response, key=_key)

        resp2 = AccessTokenResponse(access_token="token1",
                                    token_type="Bearer", expires_in=0,
                                    state=_key)
        _token_service = entity.client_get("service", 'accesstoken')
        response = _token_service.parse_response(resp2.to_urlencoded(), "urlencoded")
        _token_service.update_service_context(response, key=_key)

        request = ResourceRequest()
        BearerBody().construct(request, service=authz_service, key=_key)

        assert "access_token" in request
        assert request["access_token"] == "token1"


class TestClientSecretPost(object):
    def test_construct(self, entity):
        _token_service = entity.client_get("service", 'accesstoken')
        request = _token_service.construct(redirect_uri="http://example.com",
                                           state='ABCDE')
        csp = ClientSecretPost()
        http_args = csp.construct(request, service=_token_service)

        assert request["client_id"] == "A"
        assert request["client_secret"] == "white boarding pass"
        assert http_args is None

        request = AccessTokenRequest(code="foo",
                                     redirect_uri="http://example.com")
        http_args = csp.construct(request, service=_token_service,
                                  client_secret="another")
        assert request["client_id"] == "A"
        assert request["client_secret"] == "another"
        assert http_args is None

    def test_modify_1(self, entity):
        token_service = entity.client_get("service", 'accesstoken')
        request = token_service.construct(redirect_uri="http://example.com",
                                          state='ABCDE')
        csp = ClientSecretPost()
        # client secret not in request or kwargs
        del request["client_secret"]
        http_args = csp.construct(request, service=token_service)
        assert "client_secret" in request

    def test_modify_2(self, entity):
        token_service = entity.client_get("service", 'accesstoken')
        request = token_service.construct(redirect_uri="http://example.com",
                                          state='ABCDE')
        csp = ClientSecretPost()
        # client secret not in request or kwargs
        del request["client_secret"]
        token_service.client_get("service_context").client_secret = ""
        # this will fail
        with pytest.raises(AuthnFailure):
            http_args = csp.construct(request, service=token_service)


class TestPrivateKeyJWT(object):
    def test_construct(self, entity):
        token_service = entity.client_get("service", 'accesstoken')
        kb_rsa = KeyBundle(source='file://{}'.format(
            os.path.join(BASE_PATH, "data/keys/rsa.key")), fileformat='der')

        for key in kb_rsa:
            key.add_kid()

        _context = token_service.client_get("service_context")
        _context.keyjar.add_kb('', kb_rsa)
        _context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}
        _context.registration_response = {
            'token_endpoint_auth_signing_alg': 'RS256'}
        token_service.endpoint = "https://example.com/token"

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        http_args = pkj.construct(request, service=token_service, authn_endpoint='token_endpoint')
        assert http_args == {}
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_kb(_context.client_id, kb_rsa)
        jso = JWT(key_jar=_kj).unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        # assert _jwt.headers == {'alg': 'RS256'}
        assert jso['aud'] == [_context.provider_info['token_endpoint']]

    def test_construct_client_assertion(self, entity):
        token_service = entity.client_get("service", 'accesstoken')

        kb_rsa = KeyBundle(source='file://{}'.format(
            os.path.join(BASE_PATH, "data/keys/rsa.key")), fileformat='der')

        request = AccessTokenRequest()
        pkj = PrivateKeyJWT()
        _ca = assertion_jwt(
            token_service.client_get("service_context").client_id, kb_rsa.get('RSA'),
            "https://example.com/token", 'RS256')
        http_args = pkj.construct(request, client_assertion=_ca)
        assert http_args == {}
        assert request['client_assertion'] == _ca
        assert request['client_assertion_type'] == JWT_BEARER


class TestClientSecretJWT_TE(object):
    def test_client_secret_jwt(self, entity):
        _service_context = entity.client_get("service_context")
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}

        _service_context.registration_response = {
            'token_endpoint_auth_signing_alg': "HS256"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request,
                      service=entity.client_get("service", 'accesstoken'),
                      authn_endpoint='token_endpoint')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(_service_context.client_id, _service_context.client_secret, ['sig'])
        jso = JWT(key_jar=_kj, sign_alg='HS256').unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "exp", "iat", 'jti'])

        _rj = JWS(alg='HS256')
        info = _rj.verify_compact(
            cas, _kj.get_signing_key(issuer_id=_service_context.client_id))

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_service_context.provider_info['token_endpoint']]

    def test_get_key_by_kid(self, entity):
        _service_context = entity.client_get("service_context")
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}

        _service_context.registration_response = {
            'token_endpoint_auth_signing_alg': "HS256"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid
        _keys = _service_context.keyjar.get_issuer_keys("")
        kid = _keys[0].kid
        token_service = entity.client_get("service", 'accesstoken')
        csj.construct(request, service=token_service,
                      authn_endpoint='token_endpoint', kid=kid)
        assert "client_assertion" in request

    def test_get_key_by_kid_fail(self, entity):
        token_service = entity.client_get("service", 'accesstoken')
        _service_context = token_service.client_get("service_context")
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}

        _service_context.registration_response = {
            'token_endpoint_auth_signing_alg': "HS256"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        # get a kid
        kid = "abcdefgh"
        with pytest.raises(MissingKey):
            csj.construct(request, service=token_service,
                          authn_endpoint='token_endpoint', kid=kid)

    def test_get_audience_and_algorithm_default_alg(self, entity):
        _service_context = entity.client_get("service_context")
        _service_context.token_endpoint = "https://example.com/token"

        _service_context.provider_info = {
            'issuer': 'https://example.com/',
            'token_endpoint': "https://example.com/token"}

        _service_context.registration_response = {
            'token_endpoint_auth_signing_alg': "HS256"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        _service_context.registration_response = {}

        token_service = entity.client_get("service", 'accesstoken')

        # Add a RSA key to be able to handle default
        _kb = KeyBundle()
        _rsa_key = new_rsa_key()
        _kb.append(_rsa_key)
        _service_context.keyjar.add_kb("", _kb)
        # Since I have a RSA key this doesn't fail
        csj.construct(request, service=token_service, authn_endpoint='token_endpoint')

        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS256"
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # By client preferences
        request = AccessTokenRequest()
        _service_context.client_preferences = {"token_endpoint_auth_signing_alg": "RS512"}
        csj.construct(request, service=token_service, authn_endpoint='token_endpoint')

        _jws = factory(request["client_assertion"])
        assert _jws.jwt.headers["alg"] == "RS512"
        assert _jws.jwt.headers["kid"] == _rsa_key.kid

        # Use provider information is everything else fails
        request = AccessTokenRequest()
        _service_context.client_preferences = {}
        _service_context.provider_info["token_endpoint_auth_signing_alg_values_supported"] = [
            "ES256", "RS256"]
        csj.construct(request, service=token_service, authn_endpoint='token_endpoint')

        _jws = factory(request["client_assertion"])
        # Should be RS256 since I have no key for ES256
        assert _jws.jwt.headers["alg"] == "RS256"
        assert _jws.jwt.headers["kid"] == _rsa_key.kid


class TestClientSecretJWT_UI(object):
    def test_client_secret_jwt(self, entity):
        access_token_service = entity.client_get("service", 'accesstoken')

        _service_context = access_token_service.client_get("service_context")
        _service_context.token_endpoint = "https://example.com/token"
        _service_context.provider_info = {'issuer': 'https://example.com/',
                                          'token_endpoint': "https://example.com/token"}

        csj = ClientSecretJWT()
        request = AccessTokenRequest()

        csj.construct(request, service=access_token_service,
                      algorithm="HS256", authn_endpoint='userinfo')
        assert request["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in request
        cas = request["client_assertion"]

        _kj = KeyJar()
        _kj.add_symmetric(_service_context.client_id,
                          _service_context.client_secret,
                          usage=['sig'])
        jso = JWT(key_jar=_kj, sign_alg='HS256').unpack(cas)
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])

        _rj = JWS(alg='HS256')
        info = _rj.verify_compact(
            cas,
            _kj.get_signing_key(issuer_id=_service_context.client_id))

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info['aud'] == [_service_context.provider_info['issuer']]


class TestValidClientInfo(object):
    def test_valid_service_context(self, entity):
        _service_context = entity.client_get("service_context")

        _now = 123456  # At some time
        # Expiration time missing or 0, client_secret never expires
        # service_context.client_secret_expires_at
        assert valid_service_context(_service_context, _now)
        assert valid_service_context(_service_context, _now)
        # Expired secret
        _service_context.client_secret_expires_at = 1
        assert valid_service_context(_service_context, _now) is not True

        _service_context.client_secret_expires_at = 123455
        assert valid_service_context(_service_context, _now) is not True

        # Valid secret
        _service_context.client_secret_expires_at = 123460
        assert valid_service_context(_service_context, _now)


def test_bearer_auth():
    request = ResourceRequest(access_token="12345678")
    authn = ""
    assert bearer_auth(request, authn) == "12345678"

    request = ResourceRequest()
    authn = "Bearer abcdefghijklm"
    assert bearer_auth(request, authn) == "abcdefghijklm"

    request = ResourceRequest()
    authn = ""
    with pytest.raises(ValueError):
        bearer_auth(request, authn)
