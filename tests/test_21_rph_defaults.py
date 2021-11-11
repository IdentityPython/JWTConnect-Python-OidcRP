from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import responses
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationResponse

from oidcrp.defaults import DEFAULT_KEY_DEFS
from oidcrp.rp_handler import RPHandler

BASE_URL = "https://example.com"


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL)

    def test_pick_config(self):
        cnf = self.rph.pick_config('')
        assert cnf

    def test_init_client(self):
        client = self.rph.init_client('')
        assert set(client.client_get("services").keys()) == {
            'registration', 'provider_info', 'webfinger',
            'authorization', 'accesstoken', 'userinfo', 'refresh_token'}

        _context = client.client_get("service_context")

        assert _context.config['client_preferences'] == {
            'application_type': 'web',
            'application_name': 'rphandler',
            'response_types': ['code', 'id_token', 'id_token token', 'code id_token',
                               'code id_token token', 'code token'],
            'scope': ['openid'],
            'token_endpoint_auth_method': 'client_secret_basic'
        }

        assert list(_context.keyjar.owners()) == ['', BASE_URL]
        keys = _context.keyjar.get_issuer_keys('')
        assert len(keys) == 2

        assert _context.base_url == BASE_URL

    def test_begin(self):
        ISS_ID = "https://op.example.org"
        OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
        # The 4 steps of client_setup
        client = self.rph.init_client(ISS_ID)
        with responses.RequestsMock() as rsps:
            request_uri = '{}/.well-known/openid-configuration'.format(ISS_ID)
            _jws = ProviderConfigurationResponse(
                issuer=ISS_ID,
                authorization_endpoint='{}/authorization'.format(ISS_ID),
                jwks_uri='{}/jwks.json'.format(ISS_ID),
                response_types_supported=['code', 'id_token', 'id_token token'],
                subject_types_supported=['public'],
                id_token_signing_alg_values_supported=["RS256", "ES256"],
                token_endpoint='{}/token'.format(ISS_ID),
                registration_endpoint='{}/register'.format(ISS_ID)
            ).to_json()
            rsps.add("GET", request_uri, body=_jws, status=200)

            rsps.add("GET", '{}/jwks.json'.format(ISS_ID), body=OP_KEYS.export_jwks_as_json(),
                     status=200)

            issuer = self.rph.do_provider_info(client)

        _context = client.client_get("service_context")

        # Calculating request so I can build a reasonable response
        _req = client.client_get("service",'registration').construct_request()

        with responses.RequestsMock() as rsps:
            request_uri = _context.get('provider_info')["registration_endpoint"]
            _jws = RegistrationResponse(
                client_id="client uno", client_secret="VerySecretAndLongEnough", **_req.to_dict()
            ).to_json()
            rsps.add("POST", request_uri, body=_jws, status=200)
            self.rph.do_client_registration(client, ISS_ID)

        self.rph.issuer2rp[issuer] = client

        assert set(_context.get('behaviour').keys()) == {
            'token_endpoint_auth_method', 'response_types', 'scope', 'application_type',
            'application_name'}
        assert _context.get('client_id') == "client uno"
        assert _context.get('client_secret') == "VerySecretAndLongEnough"
        assert _context.get('issuer') == ISS_ID

        res = self.rph.init_authorization(client)
        assert set(res.keys()) == {'url', 'state'}
        p = urlparse(res["url"])
        assert p.hostname == 'op.example.org'
        assert p.path == "/authorization"
        qs = parse_qs(p.query)
        assert qs['state'] == [res['state']]
        # PKCE stuff
        assert 'code_challenge' in qs
        assert qs["code_challenge_method"] == ["S256"]

    def test_begin_2(self):
        ISS_ID = "https://op.example.org"
        OP_KEYS = build_keyjar(DEFAULT_KEY_DEFS)
        # The 4 steps of client_setup
        client = self.rph.init_client(ISS_ID)
        with responses.RequestsMock() as rsps:
            request_uri = '{}/.well-known/openid-configuration'.format(ISS_ID)
            _jws = ProviderConfigurationResponse(
                issuer=ISS_ID,
                authorization_endpoint='{}/authorization'.format(ISS_ID),
                jwks_uri='{}/jwks.json'.format(ISS_ID),
                response_types_supported=['code', 'id_token', 'id_token token'],
                subject_types_supported=['public'],
                id_token_signing_alg_values_supported=["RS256", "ES256"],
                token_endpoint='{}/token'.format(ISS_ID),
                registration_endpoint='{}/register'.format(ISS_ID)
            ).to_json()
            rsps.add("GET", request_uri, body=_jws, status=200)

            rsps.add("GET", '{}/jwks.json'.format(ISS_ID), body=OP_KEYS.export_jwks_as_json(),
                     status=200)

            issuer = self.rph.do_provider_info(client)

        _context = client.client_get("service_context")
        # Calculating request so I can build a reasonable response
        # Publishing a JWKS instead of a JWKS_URI
        _context.jwks_uri = ''
        _context.jwks = _context.keyjar.export_jwks()

        _req = client.client_get("service",'registration').construct_request()

        with responses.RequestsMock() as rsps:
            request_uri = _context.get('provider_info')["registration_endpoint"]
            _jws = RegistrationResponse(
                client_id="client uno", client_secret="VerySecretAndLongEnough", **_req.to_dict()
            ).to_json()
            rsps.add("POST", request_uri, body=_jws, status=200)
            self.rph.do_client_registration(client, ISS_ID)

        assert 'jwks' in _context.get('registration_response')