PORT = 8090
BASEURL = "https://localhost:{}".format(PORT)

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
        'issuer':"https://guarded-cliffs-8635.herokuapp.com/",
        "redirect_uris": ["{}/authz_cb/filip".format(BASEURL)],
        "post_logout_redirect_uris": ["{}/session_logout".format(BASEURL)],
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "services": DEFAULT_SERVICES,
        # "backchannel_logout_session_required": True,
        "frontchannel_logout_uri": "{}/fc_logout/filip".format(BASEURL)
    },
    "flop": {
        'issuer':"https://127.0.0.1:5000/",
        "redirect_uris": ["{}/authz_cb/flop".format(BASEURL)],
        "post_logout_redirect_uris": ["{}/session_logout".format(BASEURL)],
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "services": DEFAULT_SERVICES,
        # "backchannel_logout_session_required": True,
        "frontchannel_logout_uri": "{}/fc_logout/flop".format(BASEURL),
        "frontchannel_logout_session_required": True
    }
}

# Whether an attempt to fetch the userinfo should be made
USERINFO = True
