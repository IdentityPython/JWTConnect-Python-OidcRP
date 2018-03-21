import pytest

from http.cookiejar import FileCookieJar
from http.cookiejar import http2time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse


from oidcservice.exception import WrongContentType

from oidcrp import util

__author__ = 'Roland Hedberg'


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def test_set_cookie():
    cookiejar = FileCookieJar()
    _cookie = {"value_0": "v_0", "value_1": "v_1", "value_2": "v_2"}
    c = SimpleCookie(_cookie)

    domain_0 = ".test_domain"
    domain_1 = "test_domain"
    max_age = "09 Feb 1994 22:23:32 GMT"
    expires = http2time(max_age)
    path = "test/path"

    c["value_0"]["max-age"] = max_age
    c["value_0"]["domain"] = domain_0
    c["value_0"]["path"] = path

    c["value_1"]["domain"] = domain_1

    util.set_cookie(cookiejar, c)

    cookies = cookiejar._cookies

    c_0 = cookies[domain_0][path]["value_0"]
    c_1 = cookies[domain_1][""]["value_1"]
    c_2 = cookies[""][""]["value_2"]

    assert not (c_2.domain_specified and c_2.path_specified)
    assert c_1.domain_specified and not c_1.domain_initial_dot and not \
        c_1.path_specified
    assert c_0.domain_specified and c_0.domain_initial_dot and \
           c_0.path_specified

    assert c_0.expires == expires
    assert c_0.domain == domain_0
    assert c_0.name == "value_0"
    assert c_0.path == path
    assert c_0.value == "v_0"

    assert not c_1.expires
    assert c_1.domain == domain_1
    assert c_1.name == "value_1"
    assert c_1.path == ""
    assert c_1.value == "v_1"

    assert not c_2.expires
    assert c_2.domain == ""
    assert c_2.name == "value_2"
    assert c_2.path == ""
    assert c_2.value == "v_2"


def test_match_to():
    str0 = "abc"
    str1 = "123"
    str3 = "a1b2c3"

    test_string = "{}{}{}".format(str0, str1, str3)
    assert util.match_to_(str0, test_string)
    assert not util.match_to_(str3, test_string)

    list_of_str = ["test_0", test_string, "test_1", str1]
    assert util.match_to_(str0, list_of_str)
    assert util.match_to_(str1, list_of_str)
    assert not util.match_to_(str3, list_of_str)


def test_verify_header():
    class FakeResponse():
        def __init__(self, header):
            self.headers = {"content-type": header}
            self.text = "TEST_RESPONSE"

    json_header = "application/json"
    jwt_header = "application/jwt"
    default_header = util.DEFAULT_POST_CONTENT_TYPE
    plain_text_header = "text/plain"
    undefined_header = "undefined"

    assert util.verify_header(FakeResponse(json_header), "json") == "json"
    assert util.verify_header(FakeResponse(jwt_header), "json") == "jwt"
    assert util.verify_header(FakeResponse(jwt_header), "jwt") == "jwt"
    assert util.verify_header(FakeResponse(default_header),
                              "urlencoded") == "urlencoded"
    assert util.verify_header(FakeResponse(plain_text_header),
                              "urlencoded") == "urlencoded"

    with pytest.raises(WrongContentType):
        util.verify_header(FakeResponse(json_header), "urlencoded")
        util.verify_header(FakeResponse(jwt_header), "urlencoded")
        util.verify_header(FakeResponse(default_header), "json")
        util.verify_header(FakeResponse(plain_text_header), "jwt")
        util.verify_header(FakeResponse(undefined_header), "json")

    with pytest.raises(ValueError):
        util.verify_header(FakeResponse(json_header), "undefined")
