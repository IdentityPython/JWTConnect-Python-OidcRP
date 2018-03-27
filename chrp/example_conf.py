# BASE = "https://lingon.ladok.umu.se"

PORT = 8089

# If PORT and not default port
BASEURL = "https://localhost:{}".format(PORT)
# else
# BASEURL = "https://localhost"

# If BASE is https these has to be specified
SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

VERIFY_SSL = False

KEYDEFS = [
    {"type": "RSA", "key": '', "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]}
]

PRIVATE_JWKS_PATH = "jwks_dir/jwks.json"
PUBLIC_JWKS_PATH = 'static/jwks.json'
# information used when registering the client, this may be the same for all OPs

SERVICES = ['ProviderInfoDiscovery', 'Registration', 'Authorization',
            'AccessToken', 'RefreshAccessToken', 'UserInfo']

CLIENT_PREFS = {
    "application_type": "web",
    "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code", "id_token", "id_token token", "code id_token",
                       "code id_token token", "code token"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": ["client_secret_basic", 'client_secret_post'],
    'services': SERVICES
}

# The keys in this dictionary are the OPs short user friendly name
# not the issuer (iss) name.

CLIENTS = {
    # The ones that support webfinger, OP discovery and client registration
    # This is the default, any client that is not listed here is expected to
    # support dynamic discovery and registration.
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
    # Supports OP information lookup but not client registration
    "google": {
        "issuer": "https://accounts.google.com/",
        "client_id": "xxxxxxxxx.apps.googleusercontent.com",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],
        "client_prefs": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "allow": {
            "issuer_mismatch": True
        },
        # "userinfo_request_method": "GET",
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        }
    },
    'microsoft': {
        'issuer': 'https://login.microsoftonline.com/<tenant_id>/v2.0',
        'client_id': '242424242424',
        'client_secret': 'ipipipippipipippi',
        "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],
        "client_prefs": {
            "response_types": ["id_token"],
            "scope": ["openid"],
            "token_endpoint_auth_method": ["private_key_jwt",
                                           'client_secret_post'],
            "response_mode": 'form_post'
        },
        "allow": {
            "issuer_mismatch": True
        },
        # "userinfo_request_method": "GET",
        "services": {'ProviderInfoDiscovery': {}, 'Authorization': {}}
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
    },
    "salesforce": {
        "issuer": "https://login.salesforce.com",
        "client_id": "xxxxxxxxx.yyy",
        "client_secret": "2222222222",
        "redirect_uris": ["{}/authz_cb/salesforce".format(BASEURL)],
        "client_prefs": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        # "allow": {
        #     "issuer_mismatch": True
        # },
        # "userinfo_request_method": "GET",
        "services": {
            'ProviderInfoDiscovery': {},
            'Authorization': {},
            'AccessToken': {},
            'RefreshAccessToken': {},
            'UserInfo': {}
        },
        "keys": {'file': {'rsa': ['salesforce.key']}}
    },
    "okta": {
        "issuer": "https://dev-968755.oktapreview.com/",
        "client_id": "123456789",
        "client_secret": "abcdefgh",
        "redirect_uris": ["{}/authz_cb/okta".format(BASEURL)],
        "client_prefs": {
            "response_types": ["code"],
            "scope": ["openid", "profile", "email"],
            "token_endpoint_auth_method": ["client_secret_basic",
                                           'client_secret_post']
        },
        "provider_info": {
            "authorization_endpoint":
                "https://dev-968755.oktapreview.com/oauth2/default/v1"
                "/authorize",
            "token_endpoint":
                "https://dev-968755.oktapreview.com/oauth2/default/v1/token",
            "userinfo_endpoint":
                "https://dev-968755.oktapreview.com/oauth2/v1/userinfo"
        },
        # "userinfo_request_method": "GET",
        "services": {
            'Authorization': {},
            'AccessToken': {},
            'UserInfo': {}
        },
    }

}

# Whether an attempt to fetch the userinfo should be made
USERINFO = True
