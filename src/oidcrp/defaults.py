import hashlib
import string

SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}

DEFAULT_OIDC_SERVICES = {
    'web_finger': {'class': 'oidcrp.oidc.webfinger.WebFinger'},
    'discovery': {'class': 'oidcrp.oidc.provider_info_discovery.ProviderInfoDiscovery'},
    'registration': {'class': 'oidcrp.oidc.registration.Registration'},
    'authorization': {'class': 'oidcrp.oidc.authorization.Authorization'},
    'access_token': {'class': 'oidcrp.oidc.access_token.AccessToken'},
    'refresh_access_token': {'class': 'oidcrp.oidc.refresh_access_token.RefreshAccessToken'},
    'userinfo': {'class': 'oidcrp.oidc.userinfo.UserInfo'}
}

DEFAULT_CLIENT_PREFS = {
    'application_type': 'web',
    'application_name': 'rphandler',
    'response_types': ['code', 'id_token', 'id_token token', 'code id_token', 'code id_token token',
                       'code token'],
    'scope': ['openid'],
    'token_endpoint_auth_method': 'client_secret_basic'
}

# Using PKCE is default
DEFAULT_CLIENT_CONFIGS = {
    "": {
        "client_preferences": DEFAULT_CLIENT_PREFS,
        "add_ons": {
            "pkce": {
                "function": "oidcrp.oauth2.add_on.pkce.add_support",
                "kwargs": {
                    "code_challenge_length": 64,
                    "code_challenge_method": "S256"
                }
            }
        }
    }
}

DEFAULT_KEY_DEFS = [
    {"type": "RSA", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
]

DEFAULT_RP_KEY_DEFS = {
    'private_path': 'private/jwks.json',
    'key_defs': DEFAULT_KEY_DEFS,
    'public_path': 'static/jwks.json',
    'read_only': False
}

OIDCONF_PATTERN = "{}/.well-known/openid-configuration"
CC_METHOD = {
    'S256': hashlib.sha256,
    'S384': hashlib.sha384,
    'S512': hashlib.sha512,
}

# Map the signing context to a signing algorithm
DEF_SIGN_ALG = {"id_token": "RS256",
                "userinfo": "RS256",
                "request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "RS256"}

HTTP_ARGS = ["headers", "redirections", "connection_type"]

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
SAML2_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:saml2-bearer"

BASECHR = string.ascii_letters + string.digits
