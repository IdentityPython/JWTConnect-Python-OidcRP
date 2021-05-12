from cryptojwt.jwe.jwe import factory
from cryptojwt.key_jar import build_keyjar
from oidcmsg.oidc import AuthorizationRequest

from oidcrp.oidc.utils import construct_request_uri
from oidcrp.oidc.utils import request_object_encryption
from oidcrp.service_context import ServiceContext

KEYSPEC = [
    {"type": "RSA", "use": ["enc"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]},
]

RECEIVER = 'https://example.org/op'

KEYJAR = build_keyjar(KEYSPEC, issuer_id=RECEIVER)


def test_request_object_encryption():
    msg = AuthorizationRequest(state='ABCDE',
                               redirect_uri='https://example.com/cb',
                               response_type='code')

    conf = {
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'client_id': 'client_1',
        'client_secret': 'abcdefghijklmnop',
    }
    service_context = ServiceContext(keyjar=KEYJAR, config=conf)
    _behav = service_context.behaviour
    _behav["request_object_encryption_alg"] = 'RSA1_5'
    _behav["request_object_encryption_enc"] = "A128CBC-HS256"
    service_context.behaviour = _behav

    _jwe = request_object_encryption(msg.to_json(), service_context, target=RECEIVER)
    assert _jwe

    _decryptor = factory(_jwe)

    assert _decryptor.jwt.verify_headers(alg='RSA1_5', enc='A128CBC-HS256')


def test_construct_request_uri():
    local_dir = 'home'
    base_path = 'https://example.com/'
    a, b = construct_request_uri(local_dir, base_path)
    assert a.startswith('home') and a.endswith('.jwt')
    d, f = a.split('/')
    assert b == '{}{}'.format(base_path, f)
