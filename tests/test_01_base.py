from oidcrp import add_path
from oidcrp import load_registration_response
from oidcrp.oidc import RP


class DB(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, item):
        return self.db[item]


def test_add_path():
    assert add_path('https://example.com/', '/usr') == 'https://example.com/usr'
    assert add_path('https://example.com/', 'usr') == 'https://example.com/usr'
    assert add_path('https://example.com', '/usr') == 'https://example.com/usr'
    assert add_path('https://example.com', 'usr') == 'https://example.com/usr'


def test_load_registration_response():
    conf = {
        'redirect_uris': ['https://example.com/cli/authz_cb'],
        'client_id': 'client_1',
        'client_secret': 'abcdefghijklmnop',
        'registration_response': {'issuer': 'https://example.com'}
    }
    client = RP(DB(), config=conf)

    # test static
    load_registration_response(client)
    assert True