import os
from urllib.parse import urlsplit

import pytest
import responses
from cryptojwt.key_jar import build_keyjar

from oidcmsg.client.service_context import ServiceContext

BASE_URL = "https://entity.example.org"

def test_client_info_init():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'client_secret_wordplay',
        'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ServiceContext(BASE_URL, config=config)

    srvcnx = ServiceContext().load(ci.dump())

    for attr in config.keys():
        try:
            val = getattr(srvcnx, attr)
        except AttributeError:
            val = srvcnx.get(attr)

        assert val == config[attr]


def test_set_and_get_client_secret():
    service_context = ServiceContext()
    service_context.client_secret = 'longenoughsupersecret'
    assert service_context.client_secret == 'longenoughsupersecret'


def test_set_and_get_client_id():
    ci = ServiceContext()
    ci.client_id = 'myself'
    assert ci.client_id == 'myself'


def test_client_filename():
    config = {
        'client_id': 'client_id', 'issuer': 'issuer',
        'client_secret': 'longenoughsupersecret', 'base_url': 'https://example.com',
        'requests_dir': 'requests'
    }
    ci = ServiceContext(config=config)
    fname = ci.filename_from_webname('https://example.com/rq12345')
    assert fname == 'rq12345'


def verify_alg_support(service_context, alg, usage, typ):
    """
    Verifies that the algorithm to be used are supported by the other side.
    This will look at provider information either statically configured or
    obtained through dynamic provider info discovery.

    :param alg: The algorithm specification
    :param usage: In which context the 'alg' will be used.
        The following contexts are supported:
        - userinfo
        - id_token
        - request_object
        - token_endpoint_auth
    :param typ: Type of algorithm
        - signing_alg
        - encryption_alg
        - encryption_enc
    :return: True or False
    """

    supported = service_context.provider_info[
        "{}_{}_values_supported".format(usage, typ)]

    if alg in supported:
        return True
    else:
        return False


class TestClientInfo(object):
    @pytest.fixture(autouse=True)
    def create_client_info_instance(self):
        config = {
            'client_id': 'client_id', 'issuer': 'issuer',
            'client_secret': 'longenoughsupersecret',
            'base_url': 'https://example.com',
            'requests_dir': 'requests'
        }
        self.service_context = ServiceContext(config=config)

    def test_registration_userinfo_sign_enc_algs(self):
        self.service_context.behaviour= {
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC-HS256"
        }

        assert self.service_context.get_sign_alg('userinfo') is None
        assert self.service_context.get_enc_alg_enc('userinfo') == {
            'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'}

    def test_registration_request_object_sign_enc_algs(self):
        self.service_context.behaviour= {
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "request_object_signing_alg": "RS384"
        }

        res = self.service_context.get_enc_alg_enc('userinfo')
        # 'sign':'RS256' is an added default
        assert res == {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'}
        res = self.service_context.get_sign_alg('request_object')
        assert res == 'RS384'

    def test_registration_id_token_sign_enc_algs(self):
        self.service_context.behaviour= {
            "application_type": "web",
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "request_object_signing_alg": "RS384",
            'id_token_encrypted_response_alg': 'ECDH-ES',
            'id_token_encrypted_response_enc': "A128GCM",
            'id_token_signed_response_alg': "ES384",
        }

        res = self.service_context.get_enc_alg_enc('userinfo')
        # 'sign':'RS256' is an added default
        assert res == {'alg': 'RSA1_5', 'enc': 'A128CBC-HS256'}
        res = self.service_context.get_sign_alg('request_object')
        assert res == 'RS384'
        res = self.service_context.get_enc_alg_enc('id_token')
        assert res == {'alg': 'ECDH-ES', 'enc': 'A128GCM'}

    def test_verify_alg_support(self):
        self.service_context.provider_info= {
            "version": "3.0",
            "issuer": "https://server.example.com",
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic",
                                                      "private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["RS256",
                                                                 "ES256"],
            "userinfo_endpoint": "https://server.example.com/connect/userinfo",
            "check_session_iframe":
                "https://server.example.com/connect/check_session",
            "end_session_endpoint":
                "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwks.json",
            "registration_endpoint":
                "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address",
                                 "phone", "offline_access"],
            "response_types_supported": ["code", "code id_token", "id_token",
                                         "token id_token"],
            "acr_values_supported": ["urn:mace:incommon:iap:silver",
                                     "urn:mace:incommon:iap:bronze"],
            "subject_types_supported": ["public", "pairwise"],
            "userinfo_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
            "userinfo_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "userinfo_encryption_enc_values_supported": ["A128CBC+HS256",
                                                         "A128GCM"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256",
                                                      "HS256"],
            "id_token_encryption_alg_values_supported": ["RSA1_5", "A128KW"],
            "id_token_encryption_enc_values_supported": ["A128CBC+HS256",
                                                         "A128GCM"],
            "request_object_signing_alg_values_supported": ["none", "RS256",
                                                            "ES256"],
            "display_values_supported": ["page", "popup"],
            "claim_types_supported": ["normal", "distributed"],
            "claims_supported": ["sub", "iss", "auth_time", "acr", "name",
                                 "given_name", "family_name", "nickname",
                                 "profile",
                                 "picture", "website", "email",
                                 "email_verified",
                                 "locale", "zoneinfo",
                                 "http://example.info/claims/groups"],
            "claims_parameter_supported": True,
            "service_documentation":
                "http://server.example.com/connect/service_documentation.html",
            "ui_locales_supported": ["en-US", "en-GB", "en-CA", "fr-FR",
                                     "fr-CA"]
        }

        assert verify_alg_support(self.service_context, 'RS256', 'id_token',
                                  'signing_alg')
        assert verify_alg_support(self.service_context,
                                  'RS512', 'id_token', 'signing_alg') is False

        assert verify_alg_support(self.service_context, 'RSA1_5', 'userinfo',
                                  'encryption_alg')

        # token_endpoint_auth_signing_alg_values_supported
        assert verify_alg_support(self.service_context, 'ES256',
                                  'token_endpoint_auth', 'signing_alg')

    def test_verify_requests_uri(self):
        self.service_context.provider_info= {'issuer': 'https://example.com/'}
        url_list = self.service_context.generate_redirect_uris('/leading')
        sp = urlsplit(url_list[0])
        p = sp.path.split('/')
        assert p[0] == ''
        assert p[1] == 'leading'
        assert len(p) == 3

        # different for different OPs
        self.service_context.provider_info= {'issuer': 'https://op.example.org/'}
        url_list = self.service_context.generate_redirect_uris('/leading')
        sp = urlsplit(url_list[0])
        np = sp.path.split('/')
        assert np[0] == ''
        assert np[1] == 'leading'
        assert len(np) == 3

        assert np[2] != p[2]

    def test_import_keys_file(self):
        # Should only be one and that a symmetric key (client_secret) usable
        # for signing and encryption
        assert len(self.service_context.keyjar.get_issuer_keys('')) == 1

        file_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), 'salesforce.key'))

        keyspec = {'file': {'rsa': [file_path]}}
        self.service_context.import_keys(keyspec)

        # Now there should be 2, the second a RSA key for signing
        assert len(self.service_context.keyjar.get_issuer_keys('')) == 2

    def test_import_keys_url(self):
        assert len(self.service_context.keyjar.get_issuer_keys('')) == 1

        # One EC key for signing
        key_def = [{"type": "EC", "crv": "P-256", "use": ["sig"]}]

        keyjar = build_keyjar(key_def)

        with responses.RequestsMock() as rsps:
            _jwks_url = 'https://foobar.com/jwks.json'
            rsps.add("GET", _jwks_url, body=keyjar.export_jwks_as_json(), status=200,
                     adding_headers={"Content-Type": "application/json"})
            keyspec = {'url': {'https://foobar.com': _jwks_url}}
            self.service_context.import_keys(keyspec)
            self.service_context.keyjar.update()

            # Now there should be one belonging to https://example.com
            assert len(self.service_context.keyjar.get_issuer_keys(
                'https://foobar.com')) == 1
