import os
from http.cookies import SimpleCookie

import pytest

from oidcrp.cookie import CookieDealer
from oidcrp.http import HTTPLib
from oidcrp.util import set_cookie

_dirname = os.path.dirname(os.path.abspath(__file__))
_keydir = os.path.join(_dirname, "data", "keys")

# CLIENT_CERT = open(os.path.join(_keydir,'cert.key')).read()
# CA_CERT = open(os.path.join(_keydir, 'cacert.pem')).read()


@pytest.fixture
def cookie_dealer():
    class DummyServer():
        def __init__(self):
            self.symkey = b"0123456789012345"

    return CookieDealer(DummyServer())


# def test_ca_cert():
#     with pytest.raises(ValueError):
#         HTTPLib(CA_CERT, False, CLIENT_CERT)
#
#     _h = HTTPLib(CA_CERT, True, CLIENT_CERT)
#     assert _h.request_args["verify"] == CA_CERT


def test_cookie(cookie_dealer):
    cookie_value = "Something to pass along"
    cookie_typ = "sso"
    cookie_name = "Foobar"

    kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                       cookie_name)
    _h = HTTPLib()
    set_cookie(_h.cookiejar, SimpleCookie(kaka[1]))

    res = _h._cookies()
    assert set(res.keys()) == {'Foobar'}

    kwargs = _h.add_cookies({})
    assert 'cookies' in kwargs
    assert set(kwargs['cookies'].keys()) == {'Foobar'}


class DummyResponse(object):
    def __init__(self, status_code, data, headers):
        self.status_code = status_code
        self.data = data
        self.headers = headers


def test_set_cookie(cookie_dealer):
    cookie_value = "Something to pass along"
    cookie_typ = "sso"
    cookie_name = "Foobar"

    kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                       cookie_name)

    _h = HTTPLib()
    response = DummyResponse(200, 'OK', {"set-cookie": kaka[1]})
    _h.set_cookie(response)

    res = _h._cookies()
    assert set(res.keys()) == {'Foobar'}
