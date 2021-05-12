"""Utilities"""
from http.cookiejar import Cookie
from http.cookiejar import http2time
import importlib
import io
import json
import logging
import os
import ssl
import string
import sys
from urllib.parse import parse_qs
from urllib.parse import urlsplit
from urllib.parse import urlunsplit

from oidcmsg.exception import UnSupported
from oidcmsg.oauth2 import is_error_message
import yaml

# Since SystemRandom is not available on all systems
try:
    import SystemRandom as rnd
except ImportError:
    import random as rnd

from oidcrp.defaults import BASECHR
from oidcrp.exception import ConfigurationError
from oidcrp.exception import OidcServiceError
from oidcrp.exception import TimeFormatError
from oidcrp.exception import WrongContentType

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"
JOSE_ENCODED = "application/jose"

logger = logging.getLogger(__name__)

__author__ = 'roland'

DEFAULT_POST_CONTENT_TYPE = URL_ENCODED

PAIRS = {
    "port": "port_specified",
    "domain": "domain_specified",
    "path": "path_specified"
}

ATTRS = {
    "version": None,
    "name": "",
    "value": None,
    "port": None,
    "port_specified": False,
    "domain": "",
    "domain_specified": False,
    "domain_initial_dot": False,
    "path": "",
    "path_specified": False,
    "secure": False,
    "expires": None,
    "discard": True,
    "comment": None,
    "comment_url": None,
    "rest": "",
    "rfc2109": True
}


def token_secret_key(sid):
    return "token_secret_%s" % sid


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    chars = string.ascii_letters + string.digits
    return "".join(rnd.choice(chars) for i in range(size))


def unreserved(size=64):
    """
    Returns a string of random ascii characters, digits and unreserved
    characters

    :param size: The length of the string
    :return: string
    """

    return "".join([rnd.choice(BASECHR) for _ in range(size)])


def sanitize(str):
    return str


def get_http_url(url, req, method='GET'):
    """
    Add a query part representing the request to a url that may already contain
    a query part. Only done if the HTTP method used is 'GET' or 'DELETE'.

    :param url: The URL
    :param req: The request as a :py:class:`oidcmsg.message.Message` instance
    :param method: The HTTP method
    :return: A possibly modified URL
    """
    if method in ["GET", "DELETE"]:
        if req.keys():
            _req = req.copy()
            comp = urlsplit(str(url))
            if comp.query:
                _req.update(parse_qs(comp.query))

            _query = str(_req.to_urlencoded())
            return urlunsplit((comp.scheme, comp.netloc, comp.path,
                               _query, comp.fragment))

        return url

    return url


def get_http_body(req, content_type=URL_ENCODED):
    """
    Get the message into the format that should be places in the body part
    of a HTTP request.

    :param req: The service request as a :py:class:`oidcmsg.message.Message` instance
    :param content_type: The format of the body part.
    :return: The correctly formatted service request.
    """
    if URL_ENCODED in content_type:
        return req.to_urlencoded()

    if JSON_ENCODED in content_type:
        return req.to_json()

    if JOSE_ENCODED in content_type:
        return req  # already packaged

    raise UnSupported("Unsupported content type: '%s'" % content_type)


def load_yaml_config(filename):
    """Load a YAML configuration file."""
    with open(filename, "rt", encoding='utf-8') as file:
        config_dict = yaml.safe_load(file)
    return config_dict


def modsplit(name):
    """Split importable"""
    if ':' in name:
        _part = name.split(':')
        if len(_part) != 2:
            raise ValueError("Syntax error: {s}")
        return _part[0], _part[1]

    _part = name.split('.')
    if len(_part) < 2:
        raise ValueError("Syntax error: {s}")

    return '.'.join(_part[:-1]), _part[-1]


def importer(name):
    """Import by name"""
    _part = modsplit(name)
    module = importlib.import_module(_part[0])
    return getattr(module, _part[1])


def match_to_(val, vlist):
    if isinstance(vlist, str):
        if vlist.startswith(val):
            return True
    else:
        for v in vlist:
            if v.startswith(val):
                return True
    return False


def set_cookie(cookiejar, kaka):
    """PLaces a cookie (a cookielib.Cookie based on a set-cookie header
    line) in the cookie jar.
    Always chose the shortest expires time.

    :param cookiejar:
    :param kaka: Cookie
    """

    # default rfc2109=False
    # max-age, httponly

    for cookie_name, morsel in kaka.items():
        std_attr = ATTRS.copy()
        std_attr["name"] = cookie_name
        _tmp = morsel.coded_value
        if _tmp.startswith('"') and _tmp.endswith('"'):
            std_attr["value"] = _tmp[1:-1]
        else:
            std_attr["value"] = _tmp

        std_attr["version"] = 0
        attr = ""
        # copy attributes that have values
        try:
            for attr in morsel.keys():
                if attr in ATTRS:
                    if morsel[attr]:
                        if attr == "expires":
                            std_attr[attr] = http2time(morsel[attr])
                        else:
                            std_attr[attr] = morsel[attr]
                elif attr == "max-age":
                    if morsel[attr]:
                        std_attr["expires"] = http2time(morsel[attr])
        except TimeFormatError:
            # Ignore cookie
            logger.info(
                "Time format error on %s parameter in received cookie" % (
                    sanitize(attr),))
            continue

        for att, spec in PAIRS.items():
            if std_attr[att]:
                std_attr[spec] = True

        if std_attr["domain"] and std_attr["domain"].startswith("."):
            std_attr["domain_initial_dot"] = True

        if morsel["max-age"] == 0:
            try:
                cookiejar.clear(domain=std_attr["domain"],
                                path=std_attr["path"],
                                name=std_attr["name"])
            except ValueError:
                pass
        else:
            # Fix for Microsoft cookie error
            if "version" in std_attr:
                try:
                    std_attr["version"] = std_attr["version"].split(",")[0]
                except (TypeError, AttributeError):
                    pass

            new_cookie = Cookie(**std_attr)

            cookiejar.set_cookie(new_cookie)


def verify_header(reqresp, body_type):
    """

    :param reqresp: Class instance with attributes: ['status', 'text',
        'headers', 'url']
    :param body_type: If information returned in the body part
    :return: Verified body content type
    """
    logger.debug("resp.headers: %s" % (sanitize(reqresp.headers),))
    logger.debug("resp.txt: %s" % (sanitize(reqresp.text),))

    try:
        _ctype = reqresp.headers["content-type"]
    except KeyError:
        if body_type:
            return body_type
        else:
            return 'txt'  # reasonable default ??

    logger.debug('Expected body type: "{}"'.format(body_type))

    if body_type == "":
        if match_to_("application/json", _ctype) or match_to_(
                'application/jrd+json', _ctype):
            body_type = 'json'
        elif match_to_("application/jwt", _ctype):
            body_type = "jwt"
        elif match_to_(URL_ENCODED, _ctype):
            body_type = 'urlencoded'
        else:
            body_type = 'txt'  # reasonable default ??
    elif body_type == "json":
        if match_to_("application/json", _ctype) or match_to_(
                'application/jrd+json', _ctype):
            pass
        elif match_to_("application/jwt", _ctype):
            body_type = "jwt"
        else:
            raise WrongContentType(_ctype)
    elif body_type == "jwt":
        if not match_to_("application/jwt", _ctype):
            raise WrongContentType(_ctype)
    elif body_type == "urlencoded":
        if not match_to_(DEFAULT_POST_CONTENT_TYPE, _ctype):
            # I can live with text/plain
            if not match_to_("text/plain", _ctype):
                raise WrongContentType(_ctype)
    elif body_type == 'txt':
        if match_to_("text/plain", _ctype):
            pass
        elif match_to_("text/html", _ctype):
            pass
        else:
            raise WrongContentType(_ctype)
    else:
        raise ValueError("Unknown return format: %s" % body_type)

    logger.debug('Got body type: "{}"'.format(body_type))
    return body_type


def get_deserialization_method(reqresp):
    """

    :param reqresp: Class instance with attributes: ['status', 'text',
        'headers', 'url']
    :return: Verified body content type
    """
    logger.debug("resp.headers: %s" % (sanitize(reqresp.headers),))
    logger.debug("resp.txt: %s" % (sanitize(reqresp.text),))

    _ctype = reqresp.headers.get("content-type")
    if not _ctype:
        # let's try to detect the format
        try:
            content = reqresp.json()
            return 'json'
        except:
            return 'urlencoded'  # reasonable default ??

    if match_to_("application/json", _ctype) or match_to_(
            'application/jrd+json', _ctype):
        deser_method = 'json'
    elif match_to_("application/jwt", _ctype):
        deser_method = "jwt"
    elif match_to_("application/jose", _ctype):
        deser_method = "jose"
    elif match_to_(URL_ENCODED, _ctype):
        deser_method = 'urlencoded'
    elif match_to_("text/plain", _ctype) or match_to_("test/html", _ctype):
        deser_method = ''
    else:
        deser_method = ''  # reasonable default ??

    return deser_method


def get_value_type(http_response, body_type):
    """
    Get the HTML encoding of the response.
    Will convert Content-type into the matching deserialization methods

    :param http_response: The HTTP response
    :param body_type: Assumed body type
    :return: The deserialization method
    """
    if body_type:
        return verify_header(http_response, body_type)
    else:
        return 'urlencoded'


def load_configuration(filename):
    if filename.endswith('.yaml'):
        with open(filename) as fp:
            conf = yaml.safe_load(fp)
    elif filename.endswith('.py'):
        sys.path.insert(0, ".")
        conf = importlib.import_module(filename[:-3])
    else:
        raise ValueError('Wrong file type')

    return conf


def do_add_ons(add_ons, services):
    for key, spec in add_ons.items():
        _func = importer(spec['function'])
        _func(services, **spec['kwargs'])


def load_json(file_name):
    with open(file_name) as fp:
        js = json.load(fp)
    return js


def yaml_to_py_stream(file_name):
    d = load_yaml_config(file_name)
    fstream = io.StringIO()
    for i in d:
        section = '{} = {}\n\n'.format(i, json.dumps(d[i], indent=2))
        fstream.write(section)
    fstream.seek(0)
    return fstream


def has_method(o, name):
    """ Verifies whether an object has a specific method """
    return callable(getattr(o, name, None))


def lower_or_upper(config, param, default=None):
    res = config.get(param.lower(), default)
    if not res:
        res = config.get(param.upper(), default)
    return res


def replace(config, param, **kwargs):
    lc_param = param.lower()
    uc_param = None
    res = config.get(lc_param)
    if not res:
        uc_param = param.upper()
        res = config.get(uc_param)

    if res:
        if uc_param is not None:
            del config[uc_param]

        _keys = kwargs.keys()
        if _keys:
            # just grab one key
            _key = list(_keys)[0]
            if isinstance(res, list):
                _lst = []
                for _re in res:
                    if "{{{}}}".format(_key) in _re:
                        _lst.append(_re.format(**kwargs))
                    else:
                        _lst.append(_re)
                config[lc_param] = _lst
            else:
                if "{{{}}}".format(_key) in res:
                    config[lc_param] = res.format(**kwargs)
        else:
            config[lc_param] = res


def set_param(instance, config, param, **kwargs):
    lc_param = param.lower()
    res = config.get(lc_param)
    if not res:
        res = config.get(param.upper())

    if res:
        _keys = list(kwargs.keys())
        if _keys:
            # just grab one key
            _key = list(kwargs.keys())[0]
            if "{{{}}}".format(_key) in res:
                setattr(instance, lc_param, res.format(**kwargs))
            else:
                setattr(instance, lc_param, res)
        else:
            setattr(instance, lc_param, res)


def create_context(dir_path, config, **kwargs):
    _fname = lower_or_upper(config, "server_cert")
    if _fname:
        if _fname.startswith("/"):
            _cert_file = _fname
        else:
            _cert_file = os.path.join(dir_path, _fname)
    else:
        return None

    _fname = lower_or_upper(config, "server_key")
    if _fname:
        if _fname.startswith("/"):
            _key_file = _fname
        else:
            _key_file = os.path.join(dir_path, _fname)
    else:
        return None

    context = ssl.SSLContext(**kwargs)  # PROTOCOL_TLS by default

    _verify_user = lower_or_upper(config, "verify_user")
    if _verify_user:
        if _verify_user == "optional":
            context.verify_mode = ssl.CERT_OPTIONAL
        elif _verify_user == "required":
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            sys.exit("Unknown verify_user specification: '{}'".format(_verify_user))
        _ca_bundle = lower_or_upper(config, "ca_bundle")
        if _ca_bundle:
            context.load_verify_locations(_ca_bundle)
    else:
        context.verify_mode = ssl.CERT_NONE

    try:
        context.load_cert_chain(_cert_file, _key_file)
    except Exception as e:
        sys.exit("Error starting server. Missing cert or key. Details: {}".format(e))

    return context


def get_http_params(config):
    _ver = config.get('verify')
    if _ver is None:
        _ver = config.get('verify_ssl', True)
    params = {"verify": _ver}
    _cert = config.get('client_cert')
    _key = config.get('client_key')
    if _cert:
        if _key:
            params['cert'] = (_cert, _key)
        else:
            params['cert'] = _cert

    return params


def add_path(url, path):
    if url.endswith('/'):
        if path.startswith('/'):
            return '{}{}'.format(url, path[1:])
        else:
            return '{}{}'.format(url, path)
    else:
        if path.startswith('/'):
            return '{}{}'.format(url, path)
        else:
            return '{}/{}'.format(url, path)


def load_registration_response(client):
    """
    If the client has been statically registered that information
    must be provided during the configuration. If expected to be
    done dynamically. This method will do dynamic client registration.

    :param client: A :py:class:`oidcrp.oidc.Client` instance
    """
    if not client.client_get("service_context").get('client_id'):
        try:
            response = client.do_request('registration')
        except KeyError:
            raise ConfigurationError('No registration info')
        except Exception as err:
            logger.error(err)
            raise
        else:
            if 'error' in response:
                raise OidcServiceError(response.to_json())


def dynamic_provider_info_discovery(client):
    """
    This is about performing dynamic Provider Info discovery

    :param client: A :py:class:`oidcrp.oidc.Client` instance
    """
    try:
        client.get_service('provider_info')
    except KeyError:
        raise ConfigurationError(
            'Can not do dynamic provider info discovery')
    else:
        _context = client.client_get("service_context")
        try:
            _context.set('issuer', _context.config['srv_discovery_url'])
        except KeyError:
            pass

        response = client.do_request('provider_info')
        if is_error_message(response):
            raise OidcServiceError(response['error'])
