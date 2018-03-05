import copy
import logging
from http.cookiejar import FileCookieJar
from http.cookies import CookieError
from http.cookies import SimpleCookie

import requests

from oidcmsg.key_jar import KeyJar

from oidcservice import sanitize
from oidcservice.exception import NonFatalException

from oidcrp.util import set_cookie

__author__ = 'roland'

logger = logging.getLogger(__name__)


class HTTPLib(object):
    def __init__(self, ca_certs=None, verify_ssl=True, keyjar=None,
                 client_cert=None):
        """
        A base class for OAuth2 clients and servers

        :param ca_certs: the path to a CA_BUNDLE file or directory with
            certificates of trusted CAs
        :param verify_ssl: If True then the server SSL certificate is not
            verfied
        :param keyjar: A place to keep keys for signing/encrypting messages
        :param client_cert: local cert to use as client side certificate, as a
            single file (containing the private key and the certificate) or as
            a tuple of both file's path
        """

        self.keyjar = keyjar or KeyJar(verify_ssl=verify_ssl)

        self.request_args = {"allow_redirects": False}

        self.cookiejar = FileCookieJar()
        self.ca_certs = ca_certs

        if ca_certs:
            if verify_ssl is False:
                raise ValueError(
                    'conflict: ca_certs defined, but verify_ssl is False')

            # Instruct requests to verify certificate against the CA cert
            # bundle located at the path given by `ca_certs`.
            self.request_args["verify"] = ca_certs

        elif verify_ssl:
            # Instruct requests to verify server certificates against the
            # default CA bundle provided by 'certifi'. See
            # http://docs.python-requests.org/en/master/user/advanced/#ca
            # -certificates
            self.request_args["verify"] = True

        else:
            # Instruct requests to not perform server cert verification.
            self.request_args["verify"] = False

        self.events = None
        self.req_callback = None
        if client_cert:
            self.request_args['cert'] = client_cert

    def _cookies(self):
        """
        Return a dictionary of all the cookies I have keyed on cookie name

        :return: Dictionary
        """
        cookie_dict = {}

        for _, a in list(self.cookiejar._cookies.items()):
            for _, b in list(a.items()):
                for cookie in list(b.values()):
                    cookie_dict[cookie.name] = cookie.value

        return cookie_dict

    def __call__(self, url, method="GET", **kwargs):
        """
        Send a HTTP request to a URL using a specified method

        :param url: The URL to access
        :param method: The method to use (GET, POST, ..)
        :param kwargs: extra HTTP request parameters
        :return: A Response
        """

        # copy the default set before starting to modify it.
        _kwargs = copy.copy(self.request_args)
        if kwargs:
            _kwargs.update(kwargs)

        # If I have cookies add them all to the request
        if self.cookiejar:
            _kwargs["cookies"] = self._cookies()
            logger.debug("SENT {} COOKIES".format(len(_kwargs["cookies"])))

        # If I want to modify the request arguments based on URL, method
        # and current arguments I can use this call back function.
        if self.req_callback is not None:
            _kwargs = self.req_callback(method, url, **_kwargs)

        try:
            # Do the request
            r = requests.request(method, url, **_kwargs)
        except Exception as err:
            logger.error(
                "http_request failed: %s, url: %s, htargs: %s, method: %s" % (
                    err, url, sanitize(_kwargs), method))
            raise

        if self.events is not None:
            self.events.store('HTTP response', r, ref=url)

        try:
            _cookie = r.headers["set-cookie"]
            logger.debug("RECEIVED COOKIE")
            try:
                # add received cookies to the cookie jar
                set_cookie(self.cookiejar, SimpleCookie(_cookie))
            except CookieError as err:
                logger.error(err)
                raise NonFatalException(r, "{}".format(err))
        except (AttributeError, KeyError) as err:
            pass

        # return the response
        return r

    def send(self, url, method="GET", **kwargs):
        """
        Another name for the send method

        :param url: URL
        :param method: HTTP method
        :param kwargs: HTTP request argument
        :return: Request response
        """
        return self(url, method, **kwargs)

    def load_cookies_from_file(self, filename, ignore_discard=False,
                               ignore_expires=False):
        self.cookiejar.load(filename, ignore_discard, ignore_expires)

    def save_cookies_to_file(self, filename, ignore_discard=False,
                             ignore_expires=False):
        self.cookiejar.save(filename, ignore_discard, ignore_expires)
