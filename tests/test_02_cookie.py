import datetime
from http.cookies import SimpleCookie

import pytest

from oidcrp.cookie import CookieDealer
from oidcrp.cookie import InvalidCookieSign
from oidcrp.cookie import cookie_parts
from oidcrp.cookie import cookie_signature
from oidcrp.cookie import make_cookie
from oidcrp.cookie import parse_cookie
from oidcrp.cookie import verify_cookie_signature
from oidcrp.exception import ImproperlyConfigured

__author__ = 'roland'


@pytest.fixture
def cookie_dealer():
    class DummyServer():
        def __init__(self):
            self.symkey = b"0123456789012345"

    return CookieDealer(DummyServer())


class TestCookieDealer(object):
    def test_create_cookie_value(self, cookie_dealer):
        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        value, timestamp, typ = cookie_dealer.get_cookie_value(kaka[1],
                                                               "Foobar")

        assert (value, typ) == (cookie_value, cookie_typ)

    def test_delete_cookie(self, cookie_dealer):
        cookie_name = "Foobar"
        kaka = cookie_dealer.delete_cookie(cookie_name)
        cookie_expiration = kaka[1].split(";")[1].split("=")[1]

        now = datetime.datetime.utcnow()  #
        cookie_timestamp = datetime.datetime.strptime(
            cookie_expiration, "%a, %d-%b-%Y %H:%M:%S GMT")
        assert cookie_timestamp < now

    def test_cookie_dealer_improperly_configured(self):
        class BadServer():
            def __init__(self):
                self.symkey = ""

        with pytest.raises(ImproperlyConfigured):
            CookieDealer(BadServer())

    def test_cookie_dealer_with_domain(self):
        class DomServer():
            def __init__(self):
                self.symkey = b"0123456789012345"
                self.cookie_domain = "op.example.org"

        cookie_dealer = CookieDealer(DomServer())

        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        C = SimpleCookie()
        C.load(kaka[1])

        assert C[cookie_name]["domain"] == "op.example.org"

    def test_cookie_dealer_with_path(self):
        class DomServer():
            def __init__(self):
                self.symkey = b"0123456789012345"
                self.cookie_path = "/oidc"

        cookie_dealer = CookieDealer(DomServer())

        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        C = SimpleCookie()
        C.load(kaka[1])

        assert C[cookie_name]["path"] == "/oidc"


def test_cookie_signature():
    key = b'1234567890abcdef'
    parts = ['abc', 'def']
    sig = cookie_signature(key, *parts)
    assert verify_cookie_signature(sig, key, *parts)


def test_broken_cookie_signature():
    key = b'1234567890abcdef'
    parts = ['abc', 'def']
    sig = cookie_signature(key, *parts)
    parts.reverse()
    assert not verify_cookie_signature(sig, key, *parts)


def test_parse_cookie():
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    result = parse_cookie(name, seed, kaka)
    assert result == ('bjmc::1463043535::upm', '1463043535')


def test_parse_manipulated_cookie_payload():
    kaka = ('pyoidc=bjmc::1463043536::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    with pytest.raises(InvalidCookieSign):
        parse_cookie(name, seed, kaka)


def test_parse_manipulated_cookie_timestamp():
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043537|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = b''
    name = 'pyoidc'
    with pytest.raises(InvalidCookieSign):
        parse_cookie(name, seed, kaka)


def test_cookie_parts():
    name = 'pyoidc'
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    result = cookie_parts(name, kaka)
    assert result == ['bjmc::1463043535::upm',
                      '1463043535',
                      '18a201305fa15a96ce4048e1fbb03f7715f86499']


def test_cookie_default():
    kaka = make_cookie('test', "data", b"1234567890abcdefg")
    assert "Secure" in kaka[1]
    assert "HttpOnly" in kaka[1]
    assert "SameSite" not in kaka[1]


def test_cookie_http_only_false():
    kaka = make_cookie('test', "data", b"1234567890abcdefg", http_only=False)
    assert "Secure" in kaka[1]
    assert "HttpOnly" not in kaka[1]


def test_cookie_not_secure():
    kaka = make_cookie('test', "data", b"1234567890abcdefg", secure=False)
    assert "Secure" not in kaka[1]
    assert "HttpOnly" in kaka[1]


def test_cookie_same_site_none():
    kaka = make_cookie('test', "data", b"1234567890abcdefg", same_site="None")
    assert "SameSite=None" in kaka[1]
