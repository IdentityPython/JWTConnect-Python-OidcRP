import os

from cryptojwt.jwe.jwe import JWE
from cryptojwt.jwe.utils import alg2keytype
from oidcmsg.exception import MissingRequiredAttribute

from oidcrp.util import rndstr


def request_object_encryption(msg, service_context, **kwargs):
    """
    Created an encrypted JSON Web token with *msg* as body.

    :param msg: The mesaqg
    :param service_context:
    :param kwargs:
    :return:
    """
    try:
        encalg = kwargs["request_object_encryption_alg"]
    except KeyError:
        try:
            encalg = service_context.behaviour[
                "request_object_encryption_alg"]
        except KeyError:
            return msg

    if not encalg:
        return msg

    try:
        encenc = kwargs["request_object_encryption_enc"]
    except KeyError:
        try:
            encenc = service_context.behaviour["request_object_encryption_enc"]
        except KeyError:
            raise MissingRequiredAttribute(
                "No request_object_encryption_enc specified")

    if not encenc:
        raise MissingRequiredAttribute(
            "No request_object_encryption_enc specified")

    _jwe = JWE(msg, alg=encalg, enc=encenc)
    _kty = alg2keytype(encalg)

    try:
        _kid = kwargs["enc_kid"]
    except KeyError:
        _kid = ""

    if "target" not in kwargs:
        raise MissingRequiredAttribute("No target specified")

    if _kid:
        _keys = service_context.keyjar.get_encrypt_key(_kty,
                                                       issuer_id=kwargs["target"],
                                                       kid=_kid)
        _jwe["kid"] = _kid
    else:
        _keys = service_context.keyjar.get_encrypt_key(_kty,
                                                       issuer_id=kwargs["target"])

    return _jwe.encrypt(_keys)


def construct_request_uri(local_dir, base_path, **kwargs):
    """
    Constructs a special redirect_uri to be used when communicating with
    one OP. Each OP should get their own redirect_uris.

    :param local_dir: Local directory in which to place the file
    :param base_path: Base URL to start with
    :param kwargs:
    :return: 2-tuple with (filename, url)
    """
    _filedir = local_dir
    if not os.path.isdir(_filedir):
        os.makedirs(_filedir)
    _webpath = base_path
    _name = rndstr(10) + ".jwt"
    filename = os.path.join(_filedir, _name)
    while os.path.exists(filename):
        _name = rndstr(10)
        filename = os.path.join(_filedir, _name)
    _webname = "%s%s" % (_webpath, _name)
    return filename, _webname
