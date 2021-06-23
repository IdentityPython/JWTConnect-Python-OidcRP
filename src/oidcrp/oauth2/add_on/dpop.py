from typing import Optional
from typing import Union
import uuid

from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from cryptojwt.key_bundle import key_by_alg
from oidcmsg.message import Message
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_JSON
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.time_util import utc_time_sans_frac

from oidcrp.service_context import ServiceContext


class DPoPProof(Message):
    c_param = {
        # header
        "typ": SINGLE_REQUIRED_STRING,
        "alg": SINGLE_REQUIRED_STRING,
        "jwk": SINGLE_REQUIRED_JSON,
        # body
        "jti": SINGLE_REQUIRED_STRING,
        "htm": SINGLE_REQUIRED_STRING,
        "htu": SINGLE_REQUIRED_STRING,
        "iat": SINGLE_REQUIRED_INT
    }
    header_params = {"typ", "alg", "jwk"}
    body_params = {"jti", "htm", "htu", "iat"}

    def __init__(self, set_defaults=True, **kwargs):
        self.key = None
        Message.__init__(self, set_defaults=set_defaults, **kwargs)

        if self.key:
            pass
        elif "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

    def from_dict(self, dictionary, **kwargs):
        Message.from_dict(self, dictionary, **kwargs)

        if "jwk" in self:
            self.key = key_from_jwk_dict(self["jwk"])
            self.key.deserialize()

        return self

    def verify(self, **kwargs):
        Message.verify(self, **kwargs)
        if self["typ"] != "dpop+jwt":
            raise ValueError("Wrong type")
        if self["alg"] == "none":
            raise ValueError("'none' is not allowed as signing algorithm")

    def create_header(self) -> str:
        payload = {k: self[k] for k in self.body_params}
        _jws = JWS(payload, alg=self["alg"])
        _jws_headers = {k: self[k] for k in self.header_params}
        _signed_jwt = _jws.sign_compact(keys=[self.key], **_jws_headers)
        return _signed_jwt

    def verify_header(self, dpop_header) -> Optional["DPoPProof"]:
        _jws = factory(dpop_header)
        if _jws:
            _jwt = _jws.jwt
            if "jwk" in _jwt.headers:
                _pub_key = key_from_jwk_dict(_jwt.headers["jwk"])
                _pub_key.deserialize()
                _info = _jws.verify_compact(keys=[_pub_key], sigalg=_jwt.headers["alg"])
                for k, v in _jwt.headers.items():
                    self[k] = v

                for k, v in _info.items():
                    self[k] = v
            else:
                raise Exception()

            return self
        else:
            return None


def dpop_header(service_context: ServiceContext,
                service_endpoint: str,
                http_method: str,
                headers: Optional[dict] = None,
                **kwargs) -> dict:
    """

    :param service_context:
    :param service_endpoint:
    :param http_method:
    :param headers:
    :param kwargs:
    :return:
    """

    provider_info = service_context.provider_info
    dpop_key = service_context.add_on['dpop'].get('key')

    if not dpop_key:
        algs_supported = provider_info["dpop_signing_alg_values_supported"]
        if not algs_supported:  # does not support DPoP
            return headers

        chosen_alg = ''
        for alg in service_context.add_on['dpop']["sign_algs"]:
            if alg in algs_supported:
                chosen_alg = alg
                break

        if not chosen_alg:
            return headers

        # Mint a new key
        dpop_key = key_by_alg(chosen_alg)
        service_context.add_on['dpop']['key'] = dpop_key
        service_context.add_on['dpop']['alg'] = chosen_alg

    header_dict = {
        "typ": "dpop+jwt",
        "alg": service_context.add_on['dpop']['alg'],
        "jwk": dpop_key.serialize(),
        "jti": uuid.uuid4().hex,
        "htm": http_method,
        "htu": provider_info[service_endpoint],
        "iat": utc_time_sans_frac()
    }

    _dpop = DPoPProof(**header_dict)
    _dpop.key = dpop_key
    jws = _dpop.create_header()

    if headers is None:
        headers = {"dpop": jws}
    else:
        headers["dpop"] = jws

    return headers


def add_support(services, signing_algorithms: Optional[list] = None):
    """
    Add the necessary pieces to make pushed authorization happen.

    :param services: A dictionary with all the services the client has access to.
    :param signing_algorithms:
    """

    # Access token request should use DPoP header
    _service = services["accesstoken"]
    _context = _service.client_get("service_context")
    _context.add_on['dpop'] = {
        # "key": key_by_alg(signing_algorithm),
        "sign_algs": signing_algorithms
    }
    _service.construct_extra_headers.append(dpop_header)

    # The same for userinfo requests
    _userinfo_service = services.get("userinfo")
    if _userinfo_service:
        _userinfo_service.construct_extra_headers.append(dpop_header)
