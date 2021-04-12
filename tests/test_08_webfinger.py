import json
from urllib.parse import parse_qs, unquote_plus, urlsplit

from oidcrp.entity import Entity
import pytest
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.oidc import JRD, Link

from oidcrp.oidc import OIC_ISSUER
from oidcrp.oidc.webfinger import WebFinger
from oidcrp.service_context import ServiceContext

__author__ = 'Roland Hedberg'

SERVICE_CONTEXT = ServiceContext()


ENTITY = Entity(config={})


def test_query():
    rel = 'http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer'
    pattern = 'https://{}/.well-known/webfinger?rel={}&resource={}'
    example_oidc = {
        'example.com': ('example.com', rel, 'acct%3Aexample.com'),
        'joe@example.com': ('example.com', rel, 'acct%3Ajoe%40example.com'),
        'example.com/joe': ('example.com', rel,
                            'https%3A%2F%2Fexample.com%2Fjoe'),
        'example.com:8080': ('example.com:8080', rel,
                             'https%3A%2F%2Fexample.com%3A8080'),
        'Jane.Doe@example.com': ('example.com', rel,
                                 'acct%3AJane.Doe%40example.com'),
        'alice@example.com:8080': ('alice@example.com:8080', rel,
                                   'https%3A%2F%2Falice%40example.com%3A8080'),
        'https://example.com': ('example.com', rel,
                                'https%3A%2F%2Fexample.com'),
        'https://example.com/joe': (
            'example.com', rel, 'https%3A%2F%2Fexample.com%2Fjoe'),
        'https://joe@example.com:8080': (
            'joe@example.com:8080', rel,
            'https%3A%2F%2Fjoe%40example.com%3A8080'),
        'acct:joe@example.com': ('example.com', rel,
                                 'acct%3Ajoe%40example.com')
    }

    wf = WebFinger(ENTITY.client_get)
    for key, args in example_oidc.items():
        _q = wf.query(key)
        p = urlsplit(_q)
        assert p.netloc == args[0]
        qs = parse_qs(p.query)
        assert qs['resource'][0] == unquote_plus(args[2])
        assert qs['rel'][0] == unquote_plus(args[1])


def test_query_2():
    rel = 'http%3A%2F%2Fopenid.net%2Fspecs%2Fconnect%2F1.0%2Fissuer'
    pattern = 'https://{}/.well-known/webfinger?rel={}&resource={}'
    example_oidc = {
        # below are identifiers that are slightly off
        "example.com?query": (
            'example.com', rel, 'https%3A%2F%2Fexample.com%3Fquery'),
        "example.com#fragment": (
            'example.com', rel, 'https%3A%2F%2Fexample.com'),
        "example.com:8080/path?query#fragment":
            ('example.com:8080',
             rel, 'https%3A%2F%2Fexample.com%3A8080%2Fpath%3Fquery'),
        "http://example.com/path": (
            'example.com', rel, 'http%3A%2F%2Fexample.com%2Fpath'),
        "http://example.com?query": (
            'example.com', rel, 'http%3A%2F%2Fexample.com%3Fquery'),
        "http://example.com#fragment": (
            'example.com', rel, 'http%3A%2F%2Fexample.com'),
        "http://example.com:8080/path?query#fragment": (
            'example.com:8080', rel,
            'http%3A%2F%2Fexample.com%3A8080%2Fpath%3Fquery'),
        "nov@example.com:8080": (
            "nov@example.com:8080", rel,
            "https%3A%2F%2Fnov%40example.com%3A8080"),
        "nov@example.com/path": (
            "nov@example.com", rel,
            "https%3A%2F%2Fnov%40example.com%2Fpath"),
        "nov@example.com?query": (
            "nov@example.com", rel,
            "https%3A%2F%2Fnov%40example.com%3Fquery"),
        "nov@example.com#fragment": (
            "nov@example.com", rel,
            "https%3A%2F%2Fnov%40example.com"),
        "nov@example.com:8080/path?query#fragment": (
            "nov@example.com:8080", rel,
            "https%3A%2F%2Fnov%40example.com%3A8080%2Fpath%3Fquery"),
        "acct:nov@example.com:8080": (
            "example.com:8080", rel,
            "acct%3Anov%40example.com%3A8080"
        ),
        "acct:nov@example.com/path": (
            "example.com", rel,
            "acct%3Anov%40example.com%2Fpath"
        ),
        "acct:nov@example.com?query": (
            "example.com", rel,
            "acct%3Anov%40example.com%3Fquery"
        ),
        "acct:nov@example.com#fragment": (
            "example.com", rel,
            "acct%3Anov%40example.com"
        ),
        "acct:nov@example.com:8080/path?query#fragment": (
            "example.com:8080", rel,
            "acct%3Anov%40example.com%3A8080%2Fpath%3Fquery"
        )
    }

    wf = WebFinger(ENTITY.client_get)
    for key, args in example_oidc.items():
        _q = wf.query(key)
        p = urlsplit(_q)
        assert p.netloc == args[0]
        qs = parse_qs(p.query)
        assert qs['resource'][0] == unquote_plus(args[2])
        assert qs['rel'][0] == unquote_plus(args[1])


def test_link1():
    link = Link(
        rel="http://webfinger.net/rel/avatar",
        type="image/jpeg",
        href="http://www.example.com/~bob/bob.jpg"
    )

    assert set(link.keys()) == {'rel', 'type', 'href'}
    assert link['rel'] == "http://webfinger.net/rel/avatar"
    assert link['type'] == "image/jpeg"
    assert link['href'] == "http://www.example.com/~bob/bob.jpg"


def test_link2():
    link = Link(rel="blog", type="text/html",
                href="http://blogs.example.com/bob/",
                titles={
                    "en-us": "The Magical World of Bob",
                    "fr": "Le monde magique de Bob"
                })

    assert set(link.keys()) == {'rel', 'type', 'href', 'titles'}
    assert link['rel'] == "blog"
    assert link['type'] == "text/html"
    assert link['href'] == "http://blogs.example.com/bob/"
    assert set(link['titles'].keys()) == {'en-us', 'fr'}


def test_link3():
    link = Link(rel="http://webfinger.net/rel/profile-page",
                href="http://www.example.com/~bob/")

    assert set(link.keys()) == {'rel', 'href'}
    assert link['rel'] == "http://webfinger.net/rel/profile-page"
    assert link['href'] == "http://www.example.com/~bob/"


def test_jrd():
    jrd = JRD(
        subject="acct:bob@example.com",
        aliases=[
            "http://www.example.com/~bob/"
        ],
        properties={
            "http://example.com/ns/role/": "employee"
        },
        links=[
            Link(
                rel="http://webfinger.net/rel/avatar",
                type="image/jpeg",
                href="http://www.example.com/~bob/bob.jpg"
            ),
            Link(
                rel="http://webfinger.net/rel/profile-page",
                href="http://www.example.com/~bob/"
            )])

    assert set(jrd.keys()) == {'subject', 'aliases', 'properties', 'links'}


def test_jrd2():
    ex0 = {
        "subject": "acct:bob@example.com",
        "aliases": [
            "http://www.example.com/~bob/"
        ],
        "properties": {
            "http://example.com/ns/role/": "employee"
        },
        "links": [
            {
                "rel": "http://webfinger.net/rel/avatar",
                "type": "image/jpeg",
                "href": "http://www.example.com/~bob/bob.jpg"
            },
            {
                "rel": "http://webfinger.net/rel/profile-page",
                "href": "http://www.example.com/~bob/"
            },
            {
                "rel": "blog",
                "type": "text/html",
                "href": "http://blogs.example.com/bob/",
                "titles": {
                    "en-us": "The Magical World of Bob",
                    "fr": "Le monde magique de Bob"
                }
            },
            {
                "rel": "vcard",
                "href": "https://www.example.com/~bob/bob.vcf"
            }
        ]
    }

    jrd0 = JRD().from_json(json.dumps(ex0))

    for link in jrd0["links"]:
        if link["rel"] == "blog":
            assert link["href"] == "http://blogs.example.com/bob/"
            break


def test_extra_member_response():
    ex = {
        "subject": "acct:bob@example.com",
        "aliases": [
            "http://www.example.com/~bob/"
        ],
        "properties": {
            "http://example.com/ns/role/": "employee"
        },
        'dummy': 'foo',
        "links": [
            {
                "rel": "http://webfinger.net/rel/avatar",
                "type": "image/jpeg",
                "href": "http://www.example.com/~bob/bob.jpg"
            }]
    }

    _resp = JRD().from_json(json.dumps(ex))
    assert _resp['dummy'] == 'foo'


class TestWebFinger(object):
    def test_query_device(self):
        wf = WebFinger(ENTITY.client_get)
        request_args = {'resource': "p1.example.com"}
        _info = wf.get_request_parameters(request_args)
        p = urlsplit(_info['url'])
        assert p.netloc == request_args["resource"]
        qs = parse_qs(p.query)
        assert qs['resource'][0] == "acct:p1.example.com"
        assert qs['rel'][0] == "http://openid.net/specs/connect/1.0/issuer"

    def test_query_rel(self):
        wf = WebFinger(ENTITY.client_get)
        request_args = {'resource': "acct:bob@example.com"}
        _info = wf.get_request_parameters(request_args)
        p = urlsplit(_info['url'])
        assert p.netloc == "example.com"
        qs = parse_qs(p.query)
        assert qs['resource'][0] == "acct:bob@example.com"
        assert qs['rel'][0] == "http://openid.net/specs/connect/1.0/issuer"

    def test_query_acct(self):
        wf = WebFinger(ENTITY.client_get, rel=OIC_ISSUER)
        request_args = {'resource': "acct:carol@example.com"}
        _info = wf.get_request_parameters(request_args=request_args)

        p = urlsplit(_info['url'])
        assert p.netloc == "example.com"
        qs = parse_qs(p.query)
        assert qs['resource'][0] == "acct:carol@example.com"
        assert qs['rel'][0] == "http://openid.net/specs/connect/1.0/issuer"

    def test_query_acct_resource_kwargs(self):
        wf = WebFinger(ENTITY.client_get, rel=OIC_ISSUER)
        request_args = {}
        _info = wf.get_request_parameters(request_args=request_args,
                                          resource="acct:carol@example.com")

        p = urlsplit(_info['url'])
        assert p.netloc == "example.com"
        qs = parse_qs(p.query)
        assert qs['resource'][0] == "acct:carol@example.com"
        assert qs['rel'][0] == "http://openid.net/specs/connect/1.0/issuer"

    def test_query_acct_resource_config(self):
        wf = WebFinger(ENTITY.client_get, rel=OIC_ISSUER)
        wf.client_get("service_context").config['resource'] = "acct:carol@example.com"
        request_args = {}
        _info = wf.get_request_parameters(request_args=request_args)

        p = urlsplit(_info['url'])
        assert p.netloc == "example.com"
        qs = parse_qs(p.query)
        assert qs['resource'][0] == "acct:carol@example.com"
        assert qs['rel'][0] == "http://openid.net/specs/connect/1.0/issuer"

    def test_query_acct_no_resource(self):
        wf = WebFinger(ENTITY.client_get, rel=OIC_ISSUER)
        try:
            del wf.client_get("service_context").config['resource']
        except KeyError:
            pass
        request_args = {}

        with pytest.raises(MissingRequiredAttribute):
            wf.get_request_parameters(request_args=request_args)
