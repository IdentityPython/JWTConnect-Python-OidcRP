import pytest

from oidcrp import RPHandler

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
                                              'userinfo', 'any'}

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
        assert set(res.keys()) == {'url', 'state'}
