import copy
import logging
import requests

from http.cookiejar import FileCookieJar
from http.cookies import CookieError
from http.cookies import SimpleCookie

from oidcservice import sanitize
from oidcservice.exception import NonFatalException

from oidcrp.util import set_cookie

__author__ = 'roland'

logger = logging.getLogger(__name__)


class HTTPLib(object):
    def __init__(self, httpc_params=None):
        """
        A base class for OAuth2 clients and servers

        :param httpc_params: Default arguments to be used for HTTP requests
        """

        self.request_args = {"allow_redirects": False}
        if httpc_params:
            self.request_args.update(httpc_params)

        self.cookiejar = FileCookieJar()

        self.events = None
        self.req_callback = None

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

    def add_cookies(self, kwargs):
        if self.cookiejar:
            kwargs["cookies"] = self._cookies()
            logger.debug("SENT {} COOKIES".format(len(kwargs["cookies"])))
        return kwargs

    def run_req_callback(self, url, method, kwargs):
        if self.req_callback is not None:
            kwargs = self.req_callback(method, url, **kwargs)
        return kwargs

    def set_cookie(self, response):
        try:
            _cookie = response.headers["set-cookie"]
            logger.debug("RECEIVED COOKIE")
            try:
                # add received cookies to the cookie jar
                set_cookie(self.cookiejar, SimpleCookie(_cookie))
            except CookieError as err:
                logger.error(err)
                raise NonFatalException(response, "{}".format(err))
        except (AttributeError, KeyError) as err:
            pass

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
        self.add_cookies(kwargs)

        # If I want to modify the request arguments based on URL, method
        # and current arguments I can use this call back function.
        self.run_req_callback(url, method, kwargs)

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

        self.set_cookie(r)

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
