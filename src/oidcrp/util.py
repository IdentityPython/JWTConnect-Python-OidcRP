import logging

from http.cookiejar import Cookie
from http.cookiejar import http2time

from oidcservice import sanitize
from oidcservice.exception import TimeFormatError
from oidcservice.exception import WrongContentType

logger = logging.getLogger(__name__)

__author__ = 'roland'

URL_ENCODED = 'application/x-www-form-urlencoded'
JSON_ENCODED = "application/json"

DEFAULT_POST_CONTENT_TYPE = URL_ENCODED

PAIRS = {
    "port": "port_specified",
    "domain": "domain_specified",
    "path": "path_specified"
}


ATTRS = {"version": None,
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
         "rfc2109": True}


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

        if morsel["max-age"] is 0:
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


def get_response_body_type(response):
    try:
        _ctype = response.headers["content-type"]
    except KeyError:
        raise ValueError('Missing Content-type specification')

    body_type = ''

    if match_to_("application/json", _ctype) or match_to_(
            'application/jrd+json', _ctype):
        body_type = 'json'
    elif match_to_("application/jwt", _ctype):
        body_type = "jwt"
    elif match_to_(URL_ENCODED, _ctype):
        body_type = 'urlencoded'

    return body_type


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

    try:
        _ctype = reqresp.headers["content-type"]
    except KeyError:
        return 'txt'  # reasonable default ??

    if match_to_("application/json", _ctype) or match_to_(
            'application/jrd+json', _ctype):
        deser_method = 'json'
    elif match_to_("application/jwt", _ctype):
        deser_method = "jwt"
    elif match_to_(URL_ENCODED, _ctype):
        deser_method = 'urlencoded'
    elif match_to_("text/plain", _ctype) or match_to_("test/html", _ctype):
        deser_method = ''
    else:
        deser_method = ''  # reasonable default ??

    return deser_method


SORT_ORDER = {'RS': 0, 'ES': 1, 'HS': 2, 'PS': 3, 'no': 4}


def sort_sign_alg(alg1, alg2):
    if SORT_ORDER[alg1[0:2]] < SORT_ORDER[alg2[0:2]]:
        return -1
    elif SORT_ORDER[alg1[0:2]] > SORT_ORDER[alg2[0:2]]:
        return 1
    else:
        if alg1 < alg2:
            return -1
        elif alg1 > alg2:
            return 1
        else:
            return 0


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


