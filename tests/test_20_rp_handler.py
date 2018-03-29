from urllib.parse import urlsplit, parse_qs

import pytest
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import IdToken
from oidcservice.service_context import ServiceContext

from oidcrp import RPHandler, get_provider_specific_service

BASEURL = 'https://example.com/rp'

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": ["client_secret_basic", 'client_secret_post'],
}

CLIENT_CONFIG = {
    "": {
        "client_prefs": CLIENT_PREFS,
        "redirect_uris": None,
        "services": {
            'WebFinger': {},
            'ProviderInfoDiscovery': {},
            'Registration': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    },
    "linkedin": {
        "issuer": "https://www.linkedin.com/oauth/v2/",
        "client_id": "xxxxxxx",
        "client_secret": "yyyyyyy",
        "redirect_uris": ["{}/authz_cb/linkedin".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["r_basicprofile", "r_emailaddress"],
            "token_endpoint_auth_method": ['client_secret_post']
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
            'Authorization': {},
            'linkedin.AccessToken': {},
            'linkedin.UserInfo': {}
        }
    },
    "facebook": {
        "issuer": "https://www.facebook.com/v2.11/dialog/oauth",
        "client_id": "ccccccccc",
        "client_secret": "dddddddd",
        "behaviour": {
            "response_types": ["code"],
            "scope": ["email", "public_profile"],
            "token_endpoint_auth_method": ['']
        },
        "redirect_uris": ["{}/authz_cb/facebook".format(BASEURL)],
        "provider_info": {
            "authorization_endpoint":
                "https://www.facebook.com/v2.11/dialog/oauth",
            "token_endpoint":
                "https://graph.facebook.com/v2.11/oauth/access_token",
            "userinfo_endpoint":
                "https://graph.facebook.com/me"
        },
        'services': {
            'Authorization': {},
            'AccessToken': {'default_authn_method': ''},
            'UserInfo': {'default_authn_method': ''}
        }
    },
    'github': {
        "issuer": "https://github.com/login/oauth/authorize",
        'client_id': 'eeeeeeeee',
        'client_secret': 'aaaaaaaaaaaaa',
        "redirect_uris": ["{}/authz_cb/github".format(BASEURL)],
        "behaviour": {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
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
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {'default_authn_method': ''}
        }
    }
}


class TestRPHandler(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self):
        self.rph = RPHandler(base_url=BASEURL, client_configs=CLIENT_CONFIG)

    def test_support_webfinger(self):
        assert self.rph.supports_webfinger()

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
        assert set(client.service.keys()) == {'authorization', 'accesstoken',
                                              'userinfo', 'any',
                                              'refresh_token'}

        _context = client.service_context

        assert _context.client_id == 'eeeeeeeee'
        assert _context.client_secret == 'aaaaaaaaaaaaa'
        assert _context.issuer == "https://github.com/login/oauth/authorize"

        assert _context.provider_info
        assert set(_context.provider_info.keys()) == {
            'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint'
        }

        assert _context.behaviour == {
            "response_types": ["code"],
            "scope": ["user", "public_repo"],
            "token_endpoint_auth_method": ['']
        }

        # The key jar should only contain a symmetric key that is the clients
        # secret. 2 because one is marked for encryption and the other signing
        # usage.

        assert list(_context.keyjar.owners()) == ['']
        keys = _context.keyjar.get_issuer_keys('')
        assert len(keys) == 2
        for key in keys:
            assert key.kty == 'oct'
            assert key.key == b'aaaaaaaaaaaaa'

        assert _context.base_url == BASEURL

    def test_do_provider_info(self):
        client = self.rph.init_client('github')
        issuer = self.rph.do_provider_info(client)
        assert issuer == "https://github.com/login/oauth/authorize"

        # Make sure the service endpoints are set

        for service_type in ['authorization', 'accesstoken', 'userinfo']:
            _srv = client.service[service_type]
            _endp = client.service_context.provider_info[_srv.endpoint_name]
            assert _srv.endpoint == _endp

    def test_do_client_registration(self):
        client = self.rph.init_client('github')
        issuer = self.rph.do_provider_info(client)
        self.rph.do_client_registration(client)

        # only 2 things should have happened

        assert self.rph.hash2issuer[issuer] == issuer
        assert client.service_context.post_logout_redirect_uris == [BASEURL]

    def test_do_client_setup(self):
        client = self.rph.client_setup('github')

        _context = client.service_context

        assert _context.client_id == 'eeeeeeeee'
        assert _context.client_secret == 'aaaaaaaaaaaaa'
        assert _context.issuer == "https://github.com/login/oauth/authorize"

        assert list(_context.keyjar.owners()) == ['']
        keys = _context.keyjar.get_issuer_keys('')
        assert len(keys) == 2
        for key in keys:
            assert key.kty == 'oct'
            assert key.key == b'aaaaaaaaaaaaa'

        for service_type in ['authorization', 'accesstoken', 'userinfo']:
            _srv = client.service[service_type]
            _endp = client.service_context.provider_info[_srv.endpoint_name]
            assert _srv.endpoint == _endp

        assert self.rph.hash2issuer[_context.issuer] == _context.issuer

    def test_create_callbacks(self):
        cb = self.rph.create_callbacks('https://op.example.com/')

        assert set(cb.keys()) == {'code', 'implicit', 'form_post'}
        assert cb == {
            'code': 'https://example.com/rp/authz_cb'
                    '/7f729285244adafbf5412e06b097e0e1f92049bfc432fed0a13cbcb5661b137d',
            'implicit':
                'https://example.com/rp/authz_im_cb'
                '/7f729285244adafbf5412e06b097e0e1f92049bfc432fed0a13cbcb5661b137d',
            'form_post':
                'https://example.com/rp/authz_fp_cb'
                '/7f729285244adafbf5412e06b097e0e1f92049bfc432fed0a13cbcb5661b137d'}

        assert list(self.rph.hash2issuer.keys()) == [
            '7f729285244adafbf5412e06b097e0e1f92049bfc432fed0a13cbcb5661b137d']

        assert self.rph.hash2issuer[
                   '7f729285244adafbf5412e06b097e0e1f92049bfc432fed0a13cbcb5661b137d'
               ] == 'https://op.example.com/'

    def test_begin(self):
        res = self.rph.begin(issuer_id='github')
        assert set(res.keys()) == {'url', 'session_key'}

        _session = self.rph.session_interface.get_state(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]

        assert client.service_context.issuer == \
               "https://github.com/login/oauth/authorize"

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
        _session = self.rph.get_session_information(res['session_key'])
        assert self.rph.client_configs['github']['issuer'] == _session['iss']

    def test_finalize_auth(self):
        res = self.rph.begin(issuer_id='linkedin')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]

        auth_response = AuthorizationResponse(code='access_code',
                                              state=res['session_key'])
        resp = self.rph.finalize_auth(client, _session['iss'],
                                      auth_response.to_dict())
        assert set(resp.keys()) == {'state', 'code'}
        aresp = client.service['any'].get_item(AuthorizationResponse,
                                               'auth_response',
                                               res['session_key'])
        assert set(aresp.keys()) == {'state', 'code'}

    def test_get_client_authn_method(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        authn_method = self.rph.get_client_authn_method(client,
                                                        'token_endpoint')
        assert authn_method == ''

        res = self.rph.begin(issuer_id='linkedin')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        authn_method = self.rph.get_client_authn_method(client,
                                                        'token_endpoint')
        assert authn_method == 'client_secret_post'

    def test_get_access_token(self, httpserver):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=client.service_context.keyjar.get_signing_key('oct'),
            algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['accesstoken'].endpoint = httpserver.url

        auth_response = AuthorizationResponse(code='access_code',
                                              state=res['session_key'])
        resp = self.rph.finalize_auth(client, _session['iss'],
                                      auth_response.to_dict())

        resp = self.rph.get_access_token(client, res['session_key'])
        assert set(resp.keys()) == {'access_token', 'expires_in', 'id_token',
                                    'token_type', 'verified_id_token'}

        atresp = client.service['any'].get_item(AccessTokenResponse,
                                                'token_response',
                                                res['session_key'])
        assert set(atresp.keys()) == {'access_token', 'expires_in', 'id_token',
                                      'token_type', 'verified_id_token'}

    def test_access_and_id_token(self, httpserver):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=client.service_context.keyjar.get_signing_key('oct'),
            algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['accesstoken'].endpoint = httpserver.url

        _response = AuthorizationResponse(code='access_code',
                                          state=res['session_key'])
        auth_response = self.rph.finalize_auth(client, _session['iss'],
                                               _response.to_dict())
        resp = self.rph.get_access_and_id_token(client, auth_response)
        assert resp['access_token'] == 'accessTok'
        assert isinstance(resp['id_token'], IdToken)

    def test_access_and_id_token_by_reference(self, httpserver):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=client.service_context.keyjar.get_signing_key('oct'),
            algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['accesstoken'].endpoint = httpserver.url

        _response = AuthorizationResponse(code='access_code',
                                          state=res['session_key'])
        auth_response = self.rph.finalize_auth(client, _session['iss'],
                                               _response.to_dict())
        resp = self.rph.get_access_and_id_token(client,
                                                state=res['session_key'])
        assert resp['access_token'] == 'accessTok'
        assert isinstance(resp['id_token'], IdToken)

    def test_get_user_info(self, httpserver):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=client.service_context.keyjar.get_signing_key('oct'),
            algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600}

        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['accesstoken'].endpoint = httpserver.url

        _response = AuthorizationResponse(code='access_code',
                                          state=res['session_key'])
        auth_response = self.rph.finalize_auth(client, _session['iss'],
                                               _response.to_dict())

        token_resp = self.rph.get_access_and_id_token(client, auth_response)

        httpserver.serve_content('{"sub":"EndUserSubject"}')
        client.service['userinfo'].endpoint = httpserver.url

        userinfo_resp = self.rph.get_user_info(client, res['session_key'],
                                               token_resp['access_token'])
        assert userinfo_resp

    def test_userinfo_in_id_token(self):
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud, 'given_name': 'Diana', 'family_name': 'Krall',
                 'occupation': 'Jazz pianist'}

        idts = IdToken(**idval)

        userinfo = self.rph.userinfo_in_id_token(idts)
        assert set(userinfo.keys()) == {'sub', 'family_name', 'given_name',
                                        'occupation'}


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        return self.db[item]


def test_get_provider_specific_service():
    service_context = ServiceContext()
    _srv = get_provider_specific_service('github', 'AccessToken',
                                         service_context=service_context,
                                         state_db=DB())
    assert _srv.response_body_type == 'urlencoded'


class TestRPHandlerTier2(object):
    @pytest.fixture(autouse=True)
    def rphandler_setup(self, httpserver):
        self.rph = RPHandler(base_url=BASEURL, client_configs=CLIENT_CONFIG)
        res = self.rph.begin(issuer_id='github')
        _session = self.rph.get_session_information(res['session_key'])
        client = self.rph.issuer2rp[_session['iss']]
        _nonce = _session['auth_request']['nonce']
        _iss = _session['iss']
        _aud = client.client_id
        idval = {'nonce': _nonce, 'sub': 'EndUserSubject', 'iss': _iss,
                 'aud': _aud}

        idts = IdToken(**idval)
        _signed_jwt = idts.to_jwt(
            key=client.service_context.keyjar.get_signing_key('oct'),
            algorithm="HS256", lifetime=300)

        _info = {"access_token": "accessTok", "id_token": _signed_jwt,
                 "token_type": "Bearer", "expires_in": 3600,
                 'refresh_token': 'refreshing'}

        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['accesstoken'].endpoint = httpserver.url

        _response = AuthorizationResponse(code='access_code',
                                          state=res['session_key'])
        auth_response = self.rph.finalize_auth(client, _session['iss'],
                                               _response.to_dict())

        token_resp = self.rph.get_access_and_id_token(client, auth_response)

        httpserver.serve_content('{"sub":"EndUserSubject"}')
        client.service['userinfo'].endpoint = httpserver.url

        self.rph.get_user_info(client, res['session_key'],
                               token_resp['access_token'])
        self.session_key = res['session_key']

    def test_init_authorization(self):
        _session = self.rph.get_session_information(self.session_key)
        client = self.rph.issuer2rp[_session['iss']]
        res = self.rph.init_authorization(client,
                                          {'scope': ['openid', 'email']})
        part = urlsplit(res['url'])
        _qp = parse_qs(part.query)
        assert _qp['scope'] == ['openid email']

    def test_refresh_access_token(self, httpserver):
        _session = self.rph.get_session_information(self.session_key)
        client = self.rph.issuer2rp[_session['iss']]

        _info = {"access_token": "2nd_accessTok",
                 "token_type": "Bearer", "expires_in": 3600}
        at = AccessTokenResponse(**_info)
        httpserver.serve_content(at.to_json())
        client.service['refresh_token'].endpoint = httpserver.url

        res = self.rph.refresh_access_token(client, self.session_key,
                                            'openid email')
        assert res['access_token'] == '2nd_accessTok'