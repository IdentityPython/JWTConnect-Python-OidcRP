import json
import os
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import urlsplit

from cryptojwt.key_jar import init_key_jar
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import IdToken
from oidcmsg.oidc import JRD
from oidcmsg.oidc import Link
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import ProviderConfigurationResponse
import pytest
import responses

from oidcrp.entity import Entity
from oidcrp.oidc.registration import add_callbacks
from oidcrp.rp_handler import RPHandler

BASE_URL = 'https://example.com/rp'

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": "client_secret_basic",
    "verify_args": {"allow_sign_alg_none": True},
    "request_parameter_preference": ["request_uri", "request"]
}

CLIENT_CONFIG = {
    "": {
        "client_preferences": CLIENT_PREFS,
        "redirect_uris": None,
        "services": {
            'web_finger': {
                'class': 'oidcrp.oidc.webfinger.WebFinger'
            },
            "discovery": {
                'class': 'oidcrp.oidc.provider_info_discovery'
                         '.ProviderInfoDiscovery'
            },
            'registration': {
                'class': 'oidcrp.oidc.registration.Registration'
            },
            'authorization': {
                'class': 'oidcrp.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcrp.oidc.access_token.AccessToken'
            },
            'refresh_access_token': {
                'class': 'oidcrp.oidc.refresh_access_token'
                         '.RefreshAccessToken'
            },
            'userinfo': {
                'class': 'oidcrp.oidc.userinfo.UserInfo'
            }
        }
    },
    "linkedin": {
        "issuer": "https://www.linkedin.com/oauth/v2/",
        "client_id": "xxxxxxx",
        "client_secret": "yyyyyyyyyyyyyyyyyyyy",
        "redirect_uris": ["{}/authz_cb/linkedin".format(BASE_URL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["r_basicprofile", "r_emailaddress"],
            "token_endpoint_auth_method": 'client_secret_post'
        },
        "provider_info": {
            "authorization_endpoint":
                "https://www.linkedin.com/oauth/v2/authorization",
            "token_endpoint": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_endpoint":
                "https://api.linkedin.com/v1/people/~?format=json"
        },
        "userinfo_request_method": "GET",
        'services': {
            'authorization': {
                'class': 'oidcrp.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcrp.provider.linkedin.AccessToken'
            },
            'userinfo': {
                'class': 'oidcrp.provider.linkedin.UserInfo'
            }
        }
    },
    "facebook": {
        "issuer": "https://www.facebook.com/v2.11/dialog/oauth",
        "client_id": "ccccccccc",
        "client_secret": "dddddddddddddd",
        "behaviour": {
            "response_types": ["code"],
            "scope": ["email", "public_profile"],
            "token_endpoint_auth_method": ''
        },
        "redirect_uris": ["{}/authz_cb/facebook".format(BASE_URL)],
        "provider_info": {
            "authorization_endpoint":
                "https://www.facebook.com/v2.11/dialog/oauth",
            "token_endpoint":
                "https://graph.facebook.com/v2.11/oauth/access_token",
            "userinfo_endpoint":
                "https://graph.facebook.com/me"
        },
        'services': {
            'authorization': {
                'class': 'oidcrp.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcrp.oidc.access_token.AccessToken',
                'kwargs': {'conf': {'default_authn_method': ''}}
            },
            'userinfo': {
                'class': 'oidcrp.oidc.userinfo.UserInfo',
                'kwargs': {'conf': {'default_authn_method': ''}}
            }
        }
    },
    'github': {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASE_URL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": '',
            "verify_args": {"allow_sign_alg_none": True}
        },
        "provider_info": {
            "authorization_endpoint":
                "https://github.com/login/oauth/authorize",
            "token_endpoint":
                "https://github.com/login/oauth/access_token",
            "userinfo_endpoint":
                "https://api.github.com/user"
        },
        'services': {
            'authorization': {
                'class': 'oidcrp.oidc.authorization.Authorization',
            },
            'access_token': {
                'class': 'oidcrp.oidc.access_token.AccessToken'
            },
            'userinfo': {
                'class': 'oidcrp.oidc.userinfo.UserInfo',
                'kwargs': {'conf': {'default_authn_method': ''}}
            },
            'refresh_access_token': {
                'class': 'oidcrp.oidc.refresh_access_token.RefreshAccessToken'
            }
        }
    },
    'github2': {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASE_URL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": '',
            "verify_args": {"allow_sign_alg_none": True}
        },
        "provider_info": {
            "authorization_endpoint": "https://github.com/login/oauth/authorize",
            "token_endpoint": "https://github.com/login/oauth/access_token",
            "userinfo_endpoint": "https://api.github.com/user",
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True
        },
        'services': {
            'authorization': {
                'class': 'oidcrp.oidc.authorization.Authorization'
            },
            'access_token': {
                'class': 'oidcrp.oidc.access_token.AccessToken'
            },
            'userinfo': {
                'class': 'oidcrp.oidc.userinfo.UserInfo',
                'kwargs': {'conf': {'default_authn_method': ''}}
            },
            'refresh_access_token': {
                'class': 'oidcrp.oidc.refresh_access_token.RefreshAccessToken'
            }
        }
    }
}

KEYDEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

_dirname = os.path.dirname(os.path.abspath(__file__))

ISS = 'https://example.com'

CLI_KEY = init_key_jar(public_path='{}/pub_client.jwks'.format(_dirname),
                       private_path='{}/priv_client.jwks'.format(_dirname),
                       key_defs=KEYDEFS, issuer_id='')

LINKEDIN_KEY = init_key_jar(
    public_path='{}/pub_linkedin.jwks'.format(_dirname),
    private_path='{}/priv_linkedin.jwks'.format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG['linkedin']['issuer']
)

FACEBOOK_KEY = init_key_jar(
    public_path='{}/pub_facebook.jwks'.format(_dirname),
    private_path='{}/priv_facebook.jwks'.format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG['facebook']['issuer']
)

GITHUB_KEY = init_key_jar(
    public_path='{}/pub_github.jwks'.format(_dirname),
    private_path='{}/priv_github.jwks'.format(_dirname),
    key_defs=KEYDEFS,
    issuer_id=CLIENT_CONFIG['github']['issuer']
)


def iss_id(iss):
    return CLIENT_CONFIG[iss]['issuer']


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL, client_configs=CLIENT_CONFIG,
                             keyjar=CLI_KEY, module_dirs=['oidc'])

    def test_pick_config(self):
        cnf = self.rph.pick_config('facebook')
        assert cnf['issuer'] == "https://www.facebook.com/v2.11/dialog/oauth"

        cnf = self.rph.pick_config('linkedin')
        assert cnf['issuer'] == "https://www.linkedin.com/oauth/v2/"

        cnf = self.rph.pick_config('github')
        assert cnf['issuer'] == "https://github.com/login/oauth/authorize"

        cnf = self.rph.pick_config('')
        assert 'issuer' not in cnf

    def test_init_client(self):
        client = self.rph.init_client('github')
        assert set(client.client_get("services").keys()) == {'authorization', 'accesstoken',
                                                             'userinfo', 'refresh_token'}

        _context = client.client_get("service_context")

        assert _context.get('client_id') == 'eeeeeeeee'
        assert _context.get('client_secret') == 'aaaaaaaaaaaaaaaaaaaa'
        assert _context.get('issuer') == "https://github.com/login/oauth/authorize"

        assert _context.get('provider_info') is not None
        assert set(_context.get('provider_info').keys()) == {
            'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'
        }

        assert _context.get('behaviour') == {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": '',
            'verify_args': {'allow_sign_alg_none': True}
        }

        _github_id = iss_id('github')
        _context.keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id),
                                    _github_id)

        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.

        assert list(_context.keyjar.owners()) == ['', _github_id]
        keys = _context.keyjar.get_issuer_keys('')
        assert len(keys) == 2

        assert _context.base_url == BASE_URL

    def test_do_provider_info(self):
        client = self.rph.init_client('github')
        issuer = self.rph.do_provider_info(client)
        assert issuer == iss_id('github')

        # Make sure the service endpoints are set

        for service_type in ['authorization', 'accesstoken', 'userinfo']:
            _srv = client.client_get("service", service_type)
            _endp = client.client_get("service_context").get('provider_info')[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_do_client_registration(self):
        client = self.rph.init_client('github')
        issuer = self.rph.do_provider_info(client)
        self.rph.do_client_registration(client, 'github')

        # only 2 things should have happened

        assert self.rph.hash2issuer['github'] == issuer
        assert client.client_get("service_context").callback.get(
            "post_logout_redirect_uris") is None

    def test_do_client_setup(self):
        client = self.rph.client_setup('github')
        _github_id = iss_id('github')
        _context = client.client_get("service_context")

        assert _context.get('client_id') == 'eeeeeeeee'
        assert _context.get('client_secret') == 'aaaaaaaaaaaaaaaaaaaa'
        assert _context.get('issuer') == _github_id

        _context.keyjar.import_jwks(GITHUB_KEY.export_jwks(issuer_id=_github_id),
                                    _github_id)

        assert list(_context.keyjar.owners()) == ['', _github_id]
        keys = _context.keyjar.get_issuer_keys('')
        assert len(keys) == 2

        for service_type in ['authorization', 'accesstoken', 'userinfo']:
            _srv = client.client_get("service", service_type)
            _endp = _srv.client_get("service_context").get('provider_info')[_srv.endpoint_name]
            assert _srv.endpoint == _endp

        assert self.rph.hash2issuer['github'] == _context.get('issuer')

    def test_create_callbacks(self):
        client = self.rph.init_client('https://op.example.com/')
        _srv = client.client_get("service", "registration")
        _context = _srv.client_get("service_context")
        add_callbacks(_context, [])

        cb = _srv.client_get("service_context").callback

        assert set(cb.keys()) == {'redirect_uris', 'code', 'implicit', '__hex'}
        _hash = cb['__hex']

        assert cb['code'] == f'https://example.com/rp/authz_cb/{_hash}'
        assert cb['implicit'] == f'https://example.com/rp/authz_im_cb/{_hash}'

        assert list(_context.hash2issuer.keys()) == [_hash]

        assert _context.hash2issuer[_hash] == 'https://op.example.com/'

    def test_begin(self):
        res = self.rph.begin(issuer_id='github')
        assert set(res.keys()) == {'url', 'state'}
        _github_id = iss_id('github')

        client = self.rph.issuer2rp[_github_id]

        assert client.client_get("service_context").issuer == _github_id

        part = urlsplit(res['url'])
        assert part.scheme == 'https'
        assert part.netloc == 'github.com'
        assert part.path == '/login/oauth/authorize'
        query = parse_qs(part.query)

        assert set(query.keys()) == {'nonce', 'state', 'client_id',
                                     'redirect_uri', 'response_type', 'scope'}

        # nonce and state are created on the fly so can't check for those
        assert query['client_id'] == ['eeeeeeeee']
        assert query['redirect_uri'] == [
            'https://example.com/rp/authz_cb/github']
        assert query['response_type'] == ['code']
        assert query['scope'] == ['user public_repo openid']

    def test_get_session_information(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        assert self.rph.client_configs['github']['issuer'] == _session['iss']

    def test_get_client_from_session_key(self):
        res = self.rph.begin(issuer_id='linkedin')
        cli1 = self.rph.get_client_from_session_key(state=res['state'])
        _session = self.rph.get_session_information(res['state'])
        cli2 = self.rph.issuer2rp[_session['iss']]
        assert cli1 == cli2
        # redo
        self.rph.do_provider_info(state=res['state'])
        # get new redirect_uris
        cli2.client_get("service_context").redirect_uris = []
        self.rph.do_client_registration(state=res['state'])

    def test_finalize_auth(self):
        res = self.rph.begin(issuer_id='linkedin')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]

        auth_response = AuthorizationResponse(code='access_code',
                                              state=res['state'])
        resp = self.rph.finalize_auth(client, _session['iss'], auth_response.to_dict())
        assert set(resp.keys()) == {'state', 'code'}
        aresp = client.client_get("service_context").state.get_item(AuthorizationResponse,
                                                                    'auth_response',
                                                                    res['state'])
        assert set(aresp.keys()) == {'state', 'code'}

    def test_get_client_authn_method(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        authn_method = self.rph.get_client_authn_method(client, 'token_endpoint')
        assert authn_method == ''

        res = self.rph.begin(issuer_id='linkedin')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        authn_method = self.rph.get_client_authn_method(client,
                                                        'token_endpoint')
        assert authn_method == 'client_secret_post'

    def test_get_tokens(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]

        _github_id = iss_id('github')
        _context = client.client_get("service_context")
        _context.keyjar.import_jwks(
            GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud
        }

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key(issuer_id=_github_id), algorithm="RS256",
            lifetime=300)

        _info = {
            "access_token": "accessTok", "id_token": _signed_jwt,
            "token_type": "Bearer", "expires_in": 3600
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'accesstoken').endpoint = _url

            auth_response = AuthorizationResponse(code='access_code',
                                                  state=res['state'])
            resp = self.rph.finalize_auth(client, _session['iss'],
                                          auth_response.to_dict())

            resp = self.rph.get_tokens(res['state'], client)
            assert set(resp.keys()) == {'access_token', 'expires_in', 'id_token',
                                        'token_type', '__verified_id_token',
                                        '__expires_at'}

            atresp = client.client_get("service_context").state.get_item(
                AccessTokenResponse, 'token_response', res['state'])
            assert set(atresp.keys()) == {'access_token', 'expires_in', 'id_token',
                                          'token_type', '__verified_id_token',
                                          '__expires_at'}

    def test_access_and_id_token(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        _context = client.client_get("service_context")
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud
        }

        _github_id = iss_id('github')
        _context.keyjar.import_jwks(
            GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key('rsa', issuer_id=_github_id),
            algorithm="RS256", lifetime=300)

        _info = {
            "access_token": "accessTok", "id_token": _signed_jwt,
            "token_type": "Bearer", "expires_in": 3600
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'accesstoken').endpoint = _url

            _response = AuthorizationResponse(code='access_code',
                                              state=res['state'])
            auth_response = self.rph.finalize_auth(client, _session['iss'],
                                                   _response.to_dict())
            resp = self.rph.get_access_and_id_token(auth_response, client=client)
            assert resp['access_token'] == 'accessTok'
            assert isinstance(resp['id_token'], IdToken)

    def test_access_and_id_token_by_reference(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        _context = client.client_get("service_context")
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud
        }

        _github_id = iss_id('github')
        _context.keyjar.import_jwks(
            GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key('rsa', issuer_id=_github_id),
            algorithm="RS256", lifetime=300)

        _info = {
            "access_token": "accessTok", "id_token": _signed_jwt,
            "token_type": "Bearer", "expires_in": 3600
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'accesstoken').endpoint = _url

            _response = AuthorizationResponse(code='access_code',
                                              state=res['state'])
            _ = self.rph.finalize_auth(client, _session['iss'],
                                       _response.to_dict())
            resp = self.rph.get_access_and_id_token(state=res['state'])
            assert resp['access_token'] == 'accessTok'
            assert isinstance(resp['id_token'], IdToken)

    def test_get_user_info(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        _context = client.client_get("service_context")
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud
        }

        _github_id = iss_id('github')
        _context.keyjar.import_jwks(
            GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key('rsa', issuer_id=_github_id),
            algorithm="RS256", lifetime=300)

        _info = {
            "access_token": "accessTok", "id_token": _signed_jwt,
            "token_type": "Bearer", "expires_in": 3600
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'accesstoken').endpoint = _url

            _response = AuthorizationResponse(code='access_code',
                                              state=res['state'])
            auth_response = self.rph.finalize_auth(client, _session['iss'],
                                                   _response.to_dict())

            token_resp = self.rph.get_access_and_id_token(auth_response,
                                                          client=client)

        _url = "https://github.com/user_info"
        with responses.RequestsMock() as rsps:
            rsps.add("GET", _url, body='{"sub":"EndUserSubject"}',
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'userinfo').endpoint = _url

            userinfo_resp = self.rph.get_user_info(res['state'], client,
                                                   token_resp['access_token'])
            assert userinfo_resp

    def test_userinfo_in_id_token(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        _context = client.client_get("service_context")
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud, 'given_name': 'Diana', 'family_name': 'Krall',
            'occupation': 'Jazz pianist'
        }

        idts = IdToken(**idval)

        userinfo = self.rph.userinfo_in_id_token(idts)
        assert set(userinfo.keys()) == {'sub', 'family_name', 'given_name',
                                        'occupation'}


def test_get_provider_specific_service():
    srv_desc = {
        'access_token': {
            'class': 'oidcrp.provider.github.AccessToken'
        }
    }
    entity = Entity(services=srv_desc)
    assert entity.client_get("service", 'accesstoken').response_body_type == 'urlencoded'


class TestRPHandlerTier2(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['state'])
        client = self.rph.issuer2rp[_session['iss']]
        _context = client.client_get("service_context")
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = _context.client_id
        idval = {
            'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
            'aud': _aud
        }

        _github_id = iss_id('github')
        _context.keyjar.import_jwks(
            GITHUB_KEY.export_jwks(issuer_id=_github_id), _github_id)

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=GITHUB_KEY.get_signing_key('rsa', issuer_id=_github_id),
            algorithm="RS256", lifetime=300)

        _info = {
            "access_token": "accessTok", "id_token": _signed_jwt,
            "token_type": "Bearer", "expires_in": 3600,
            'refresh_token': 'refreshing'
        }

        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            client.client_get("service", 'accesstoken').endpoint = _url

            _response = AuthorizationResponse(code='access_code',
                                              state=res['state'])
            auth_response = self.rph.finalize_auth(client, _session['iss'],
                                                   _response.to_dict())

            token_resp = self.rph.get_access_and_id_token(auth_response,
                                                          client=client)

        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("GET", _url, body='{"sub":"EndUserSubject"}',
                     adding_headers={"Content-Type": "application/json"}, status=200)

            client.client_get("service", 'userinfo').endpoint = _url
            self.rph.get_user_info(res['state'], client,
                                   token_resp['access_token'])
            self.state = res['state']

    def test_init_authorization(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session['iss']]
        res = self.rph.init_authorization(
            client, req_args={'scope': ['openid', 'email']})
        part = urlsplit(res['url'])
        _qp = parse_qs(part.query)
        assert _qp['scope'] == ['openid email']

    def test_refresh_access_token(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session['iss']]

        _info = {
            "access_token": "2nd_accessTok",
            "token_type": "Bearer", "expires_in": 3600
        }
        at = AccessTokenResponse(**_info)
        _url = "https://github.com/token"
        with responses.RequestsMock() as rsps:
            rsps.add("POST", _url, body=at.to_json(),
                     adding_headers={"Content-Type": "application/json"}, status=200)

            client.client_get("service", 'refresh_token').endpoint = _url
            res = self.rph.refresh_access_token(self.state, client, 'openid email')
            assert res['access_token'] == '2nd_accessTok'

    def test_get_user_info(self):
        _session = self.rph.get_session_information(self.state)
        client = self.rph.issuer2rp[_session['iss']]

        _url = "https://github.com/userinfo"
        with responses.RequestsMock() as rsps:
            rsps.add("GET", _url, body='{"sub":"EndUserSubject", "mail":"foo@example.com"}',
                     adding_headers={"Content-Type": "application/json"}, status=200)
            client.client_get("service", 'userinfo').endpoint = _url

            resp = self.rph.get_user_info(self.state, client)
            assert set(resp.keys()) == {'sub', 'mail'}
            assert resp['mail'] == 'foo@example.com'

    def test_has_active_authentication(self):
        assert self.rph.has_active_authentication(self.state)

    def test_get_valid_access_token(self):
        (token, expires_at) = self.rph.get_valid_access_token(self.state)
        assert token == 'accessTok'
        assert expires_at > 0


class MockResponse():
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


class MockOP(object):
    def __init__(self, issuer, keyjar=None):
        self.keyjar = keyjar
        self.issuer = issuer
        self.state = ''
        self.nonce = ''
        self.get_response = {}
        self.register_get_response('default', 'OK', 200)
        self.post_response = {}
        self.register_post_response('default', 'OK', 200)

    def register_get_response(self, path, data, status_code=200, headers=None):
        _headers = headers or {}
        self.get_response[path] = MockResponse(status_code, data, _headers)

    def register_post_response(self, path, data, status_code=200, headers=None):
        _headers = headers or {}
        self.post_response[path] = MockResponse(status_code, data, _headers)

    def __call__(self, url, method="GET", data=None, headers=None, **kwargs):
        if method == 'GET':
            p = urlparse(url)
            try:
                _resp = self.get_response[p.path]
            except KeyError:
                _resp = self.get_response['default']

            if callable(_resp.text):
                _data = _resp.text(data)
                _resp = MockResponse(_resp.status_code, _data, _resp.headers)

            return _resp
        elif method == 'POST':
            p = urlparse(url)
            try:
                _resp = self.post_response[p.path]
            except KeyError:
                _resp = self.post_response['default']

            if callable(_resp.text):
                _data = _resp.text(data)
                _resp = MockResponse(_resp.status_code, _data, _resp.headers)

            return _resp


def construct_access_token_response(nonce, issuer, client_id, key_jar):
    _aud = client_id

    idval = {
        'nonce': nonce, 'sub': 'EndUserSubject', 'iss': issuer,
        'aud': _aud
    }

    idts = IdToken(**idval)
    _signed_jwt = idts.to_jwt(
        key=key_jar.get_signing_key('rsa', issuer_id=issuer),
        algorithm="RS256", lifetime=300)

    _info = {
        "access_token": "accessTok", "id_token": _signed_jwt,
        "token_type": "Bearer", "expires_in": 3600
    }

    return AccessTokenResponse(**_info)


def registration_callback(data):
    _req = json.loads(data)
    # add client_id and client_secret
    _req['client_id'] = 'client1'
    _req['client_secret'] = "ClientSecretString"
    return json.dumps(_req)


def test_rphandler_request_uri():
    rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
    res = rph.begin(issuer_id='github2', behaviour_args={"request_param": "request_uri"})
    _session = rph.get_session_information(res['state'])
    _url = res["url"]
    _qp = parse_qs(urlparse(_url).query)
    assert 'request_uri' in _qp


def test_rphandler_request():
    rph = RPHandler(BASE_URL, CLIENT_CONFIG, keyjar=CLI_KEY)
    res = rph.begin(issuer_id='github2',
                    behaviour_args={"request_param": "request"})
    _session = rph.get_session_information(res['state'])
    _url = res["url"]
    _qp = parse_qs(urlparse(_url).query)
    assert 'request' in _qp


class TestRPHandlerWithMockOP(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.issuer = 'https://github.com/login/oauth/authorize'
        self.mock_op = MockOP(issuer=self.issuer)
        self.rph = RPHandler(BASE_URL, client_configs=CLIENT_CONFIG,
                             http_lib=self.mock_op, keyjar=CLI_KEY)

    def test_finalize(self):
        auth_query = self.rph.begin(issuer_id='github')
        #  The authorization query is sent and after successful authentication
        client = self.rph.get_client_from_session_key(
            state=auth_query['state'])
        # register a response
        p = urlparse(
            CLIENT_CONFIG['github']['provider_info']['authorization_endpoint'])
        self.mock_op.register_get_response(p.path, 'Redirect', 302)

        _ = client.http(auth_query['url'])

        #  the user is redirected back to the RP with a positive response
        auth_response = AuthorizationResponse(code='access_code',
                                              state=auth_query['state'])

        # need session information and the client instance
        _session = self.rph.get_session_information(auth_response['state'])
        client = self.rph.get_client_from_session_key(
            state=auth_response['state'])

        # Faking
        resp = construct_access_token_response(
            _session['auth_request']['nonce'], issuer=self.issuer,
            client_id=CLIENT_CONFIG['github']['client_id'],
            key_jar=GITHUB_KEY)

        p = urlparse(
            CLIENT_CONFIG['github']['provider_info']['token_endpoint'])
        self.mock_op.register_post_response(
            p.path, resp.to_json(), 200, {'content-type': "application/json"}
        )

        _info = OpenIDSchema(sub='EndUserSubject',
                             given_name='Diana',
                             family_name='Krall',
                             occupation='Jazz pianist')
        p = urlparse(
            CLIENT_CONFIG['github']['provider_info']['userinfo_endpoint'])
        self.mock_op.register_get_response(
            p.path, _info.to_json(), 200, {'content-type': "application/json"})

        _github_id = iss_id('github')
        client.client_get("service_context").keyjar.import_jwks(GITHUB_KEY.export_jwks(
            issuer_id=_github_id), _github_id)

        # do the rest (= get access token and user info)
        # assume code flow
        resp = self.rph.finalize(_session['iss'], auth_response.to_dict())

        assert set(resp.keys()) == {'userinfo', 'state', 'token', 'id_token', 'session_state'}

    def test_dynamic_setup(self):
        user_id = 'acct:foobar@example.com'
        _link = Link(rel="http://openid.net/specs/connect/1.0/issuer",
                     href="https://server.example.com")
        webfinger_response = JRD(subject=user_id,
                                 links=[_link])
        self.mock_op.register_get_response(
            '/.well-known/webfinger', webfinger_response.to_json(), 200,
            {'content-type': "application/json"})

        resp = {
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "subject_types_supported": ['public'],
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "userinfo_endpoint": "https://server.example.com/connect/user",
            "check_id_endpoint": "https://server.example.com/connect/check_id",
            "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwk.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address", "phone"],
            "response_types_supported": ["code", "code id_token", "token id_token"],
            "acrs_supported": ["1", "2", "http://id.incommon.org/assurance/bronze"],
            "user_id_types_supported": ["public", "pairwise"],
            "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256",
                                                      "A128CBC", "A128KW",
                                                      "RSA1_5"],
            "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"]
        }

        pcr = ProviderConfigurationResponse(**resp)
        self.mock_op.register_get_response(
            '/.well-known/openid-configuration', pcr.to_json(), 200,
            {'content-type': "application/json"})

        self.mock_op.register_post_response(
            '/connect/register', registration_callback, 200,
            {'content-type': "application/json"})

        auth_query = self.rph.begin(user_id=user_id)
        assert auth_query

    def test_dynamic_setup_redirect_uri(self):
        user_id = 'acct:foobar@example.com'
        _link = Link(rel="http://openid.net/specs/connect/1.0/issuer",
                     href="https://server.example.com")
        webfinger_response = JRD(subject=user_id, links=[_link])
        self.mock_op.register_get_response(
            '/.well-known/webfinger', webfinger_response.to_json(), 200,
            {'content-type': "application/json"})

        resp = {
            "authorization_endpoint":
                "https://server.example.com/connect/authorize",
            "issuer": "https://server.example.com",
            "subject_types_supported": ['public'],
            "token_endpoint": "https://server.example.com/connect/token",
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"],
            "userinfo_endpoint": "https://server.example.com/connect/user",
            "check_id_endpoint": "https://server.example.com/connect/check_id",
            "refresh_session_endpoint": "https://server.example.com/connect/refresh_session",
            "end_session_endpoint": "https://server.example.com/connect/end_session",
            "jwks_uri": "https://server.example.com/jwk.json",
            "registration_endpoint": "https://server.example.com/connect/register",
            "scopes_supported": ["openid", "profile", "email", "address", "phone"],
            "response_types_supported": ["code", "code id_token", "token id_token"],
            "acrs_supported": ["1", "2", "http://id.incommon.org/assurance/bronze"],
            "user_id_types_supported": ["public", "pairwise"],
            "userinfo_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "id_token_signing_alg_values_supported": ["HS256", "RS256",
                                                      "A128CBC", "A128KW",
                                                      "RSA1_5"],
            "request_object_algs_supported": ["HS256", "RS256", "A128CBC", "A128KW", "RSA1_5"],
            "request_parameter_supported": True,
            "request_uri_parameter_supported": True,
            "require_request_uri_registration": True
        }

        pcr = ProviderConfigurationResponse(**resp)
        self.mock_op.register_get_response(
            '/.well-known/openid-configuration', pcr.to_json(), 200,
            {'content-type': "application/json"})

        self.mock_op.register_post_response(
            '/connect/register', registration_callback, 200,
            {'content-type': "application/json"})

        res = self.rph.begin(user_id=user_id,
                             behaviour_args={
                                 "request_param": "request",
                                 "request_object_signing_alg": "RS256"})
        assert res

        _url = res["url"]
        _qp = parse_qs(urlparse(_url).query)
        assert 'request' in _qp
