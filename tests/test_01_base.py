from oidcmsg.util import add_path

from oidcrp.oidc import RP
from oidcrp.rp_handler import load_registration_response


def test_load_registration_response():
    conf = {
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'client_id': 'client_1',
        'client_secret': 'abcdefghijklmnop',
        'registration_response': {'issuer': 'https://example.com'}
    }
    client = RP(config=conf)

    # test static
    load_registration_response(client)
    assert True
