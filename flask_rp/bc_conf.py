PORT = 8090
BASEURL = "https://127.0.0.1:{}".format(PORT)

# If BASE is https these has to be specified
SERVER_CERT = "certs/cert.pem"
SERVER_KEY = "certs/key.pem"
CA_BUNDLE = None

# This is just for testing an local usage. In all other cases it MUST be True
VERIFY_SSL = False

KEYDEFS = [{"type": "RSA", "key": '', "use": ["sig"]},
           {"type": "EC", "crv": "P-256", "use": ["sig"]}]

HTML_HOME = 'html'

SECRET_KEY = 'secret_key'
SESSION_COOKIE_NAME = 'rp_session'

PREFERRED_URL_SCHEME = 'https'

OIDC_KEYS = {
    'private_path': "./priv/jwks.json",
    'key_defs': KEYDEFS,
    'public_path': './static/jwks.json'
}

PUBLIC_JWKS_PATH = '{}/{}'.format(BASEURL, OIDC_KEYS['public_path'])

# # information used when registering the client, this may be the same for all OPs
#
DEFAULT_CLIENT_PREFS = {
    "application_type": "web", "application_name": "rphandler",
    "contacts": ["ops@example.com"],
    "response_types": ["code"],
    "scope": ["openid", "profile", "email", "address", "phone"],
    "token_endpoint_auth_method": ["client_secret_basic",
                                   'client_secret_post']
}

# Default set if nothing else is specified
DEFAULT_SERVICES = {
    'ProviderInfoDiscovery': {}, 'Registration': {},
    'Authorization': {}, 'AccessToken': {},
    'RefreshAccessToken': {}, 'UserInfo': {},
    'EndSession': {}
}

CLIENT_CONFIG = {
    'client_preferences': DEFAULT_CLIENT_PREFS,
    'services': DEFAULT_SERVICES
}

# The keys in this dictionary are the OPs short user friendly name
# not the issuer (iss) name.
# The special key '' is ued for OPs that support dynamic interactions.

CLIENTS = {
    # The ones that support web finger, OP discovery and client registration
    # This is the default, any client that is not listed here is expected to
    # support dynamic discovery and registration.
    "": CLIENT_CONFIG,
    "filip": {
        'issuer': "https://guarded-cliffs-8635.herokuapp.com/",
        "redirect_uris": ["{}/authz_cb/filip".format(BASEURL)],
        "post_logout_redirect_uris": ["{}/session_logout".format(BASEURL)],
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "services": DEFAULT_SERVICES,
        # "backchannel_logout_session_required": True,
        "backchannel_logout_uri": "{}/bc_logout".format(BASEURL)
    },
    "flop": {
        'issuer': "https://127.0.0.1:5000/",
        "redirect_uris": ["{}/authz_cb/flop".format(BASEURL)],
        "post_logout_redirect_uris": ["{}/session_logout".format(BASEURL)],
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "services": DEFAULT_SERVICES,
        # "backchannel_logout_session_required": True,
        "backchannel_logout_uri": "{}/bc_logout/flop".format(BASEURL)
    },
    "filip_local": {
        'issuer': "http://localhost:3000/",
        "redirect_uris": ["{}/authz_cb/filip_local".format(BASEURL)],
        "post_logout_redirect_uris": ["{}/session_logout".format(BASEURL)],
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "services": DEFAULT_SERVICES,
        # "backchannel_logout_session_required": True,
        "backchannel_logout_uri": "{}/bc_logout".format(BASEURL)
    },
    'bobcat': {
        'issuer': 'https://127.0.0.1:8443/',
        "client_id": "client3",
        "client_secret": "2222222222222222222222222222222222222222",
        "redirect_uris": ["{}/authz_cb/bobcat".format(BASEURL)],
        "client_preferences": {
            "response_types": ["code"],
            "scope": ["openid", "offline_access"],
            "token_endpoint_auth_method": "client_secret_basic"
        },
        "services": {
            'ProviderInfoDiscovery': {}, 'Authorization': {}, 'AccessToken': {},
            'RefreshAccessToken': {}
        }
    }
}

# Whether an attempt to fetch the userinfo should be made
USERINFO = True
