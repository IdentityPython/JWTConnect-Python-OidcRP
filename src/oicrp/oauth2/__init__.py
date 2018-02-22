import cherrypy
import logging

from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.client_info import ClientInfo
from oiccli.exception import OicCliError
from oiccli.exception import ParseError
from oiccli.oauth2 import service
from oiccli.service import build_services
from oiccli.service import REQUEST_INFO
from oiccli.service import SUCCESSFUL

from oicmsg.key_jar import KeyJar

from oicrp.http import HTTPLib
from oicrp.util import get_deserialization_method

__author__ = 'Roland Hedberg'

logger = logging.getLogger(__name__)

Version = "2.0"

DEFAULT_SERVICES = [
    ('Authorization', {}),
    ['AccessToken', {}],
    ('RefreshAccessToken', {}),
    ('ProviderInfoDiscovery', {})
]


class ExpiredToken(Exception):
    pass


# =============================================================================


class Client(object):
    def __init__(self, ca_certs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, config=None, client_cert=None, httplib=None,
                 services=None, service_factory=None, jwks_uri=''):
        """

        :param ca_certs: Certificates used to verify HTTPS certificates
        :param client_authn_method: Methods that this client can use to
            authenticate itself. It's a dictionary with method names as
            keys and method classes as values.
        :param keyjar: A py:class:`oicmsg.key_jar.KeyJar` instance
        :param verify_ssl: Whether the SSL certificate should be verified.
        :param config: Configuration information passed on to the
            :py:class:`oiccli.client_info.ClientInfo` initialization
        :param client_cert: Certificate used by the HTTP client
        :param httplib: A HTTP client to use
        :param services: A list of service definitions
        :param service_factory: A factory to use when building the
            :py:class:`oiccli.service.Service` instances
        :param jwks_uri: A jwks_uri
        :return: Client instance
        """

        self.http = httplib or HTTPLib(ca_certs=ca_certs,
                                       verify_ssl=verify_ssl,
                                       client_cert=client_cert,
                                       keyjar=keyjar)

        if not keyjar:
            keyjar = KeyJar()

        keyjar.verify_ssl = verify_ssl

        self.events = None
        self.client_info = ClientInfo(keyjar, config=config, jwks_uri=jwks_uri)
        if self.client_info.client_id:
            self.client_id = self.client_info.client_id
        _cam = client_authn_method or CLIENT_AUTHN_METHOD
        self.service_factory = service_factory or service.factory
        _srvs = services or DEFAULT_SERVICES

        self.service = build_services(_srvs, self.service_factory, self.http,
                                      keyjar, _cam)

        self.client_info.service = self.service

        self.verify_ssl = verify_ssl

    def construct(self, request_type, request_args=None, extra_args=None,
                  **kwargs):
        try:
            self.service[request_type]
        except KeyError:
            raise NotImplemented(request_type)

        met = getattr(self, 'construct_{}_request'.format(request_type))
        return met(self.client_info, request_args, extra_args, **kwargs)

    def do_request(self, request_type, scope="", response_body_type="",
                   method="", request_args=None, extra_args=None,
                   http_args=None, authn_method="", **kwargs):

        _srv = self.service[request_type]
        if not method:
            method = _srv.http_method

        _info = _srv.do_request_init(
            self.client_info, method=method, scope=scope,
            request_args=request_args, extra_args=extra_args,
            authn_method=authn_method, http_args=http_args, **kwargs)

        if not response_body_type:
            response_body_type = _srv.response_body_type

        logger.debug('do_request info: {}'.format(_info))

        try:
            _body = _info['body']
        except KeyError:
            _body = None

        return self.service_request(_srv,
                                    _info['uri'], method, _body,
                                    response_body_type,
                                    http_args=_info['http_args'],
                                    client_info=self.client_info,
                                    **kwargs)

    def set_client_id(self, client_id):
        self.client_id = client_id
        self.client_info.client_id = client_id

    def service_request(self, service, url, method="GET", body=None,
                        response_body_type="", http_args=None, client_info=None,
                        **kwargs):
        """
        The method that sends the request and handles the response returned.
        This assumes a synchronous request-response exchange.

        :param url: The URL to which the request should be sent
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param response_body_type: The expected format of the body of the
            return message
        :param http_args: Arguments for the HTTP client
        :param client_info: A py:class:`oiccli.client_info.ClientInfo` instance
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        logger.debug(REQUEST_INFO.format(url, method, body, http_args))

        try:
            resp = self.http(url, method, data=body, **http_args)
        except Exception as err:
            logger.error('Exception on request: {}'.format(err))
            raise

        if "keyjar" not in kwargs:
            kwargs["keyjar"] = service.keyjar
        if not response_body_type:
            response_body_type = service.response_body_type

        return self.parse_request_response(service, resp, client_info,
                                           response_body_type, **kwargs)

    def parse_request_response(self, service, reqresp, client_info,
                               response_body_type='', state="", **kwargs):
        """
        Deal with a self.http response. The response are expected to
        follow a special pattern, having the attributes:

            - headers (list of tuples with headers attributes and their values)
            - status_code (integer)
            - text (The text version of the response)
            - url (The calling URL)

        :param service: A :py:class:`oiccli.service.Service` instance
        :param reqresp: The HTTP request response
        :param client_info: Information about the client/server session
        :param response_body_type: If response in body one of 'json', 'jwt' or
            'urlencoded'
        :param state: Session identifier
        :param kwargs: Extra keyword arguments
        :return:
        """

        # if not response_body_type:
        #     response_body_type = self.response_body_type

        if reqresp.status_code in SUCCESSFUL:
            logger.debug('response_body_type: "{}"'.format(response_body_type))
            _deser_method = get_deserialization_method(reqresp)

            if _deser_method != response_body_type:
                logger.warning(
                    'Not the body type I expected: {} != {}'.format(
                        _deser_method, response_body_type))
            if _deser_method in ['json', 'jwt', 'urlencoded']:
                value_type = _deser_method
            else:
                value_type = response_body_type

            logger.debug('Successful response: {}'.format(reqresp.text))

            try:
                return service.parse_response(reqresp.text, client_info,
                                              value_type, state, **kwargs)
            except Exception as err:
                logger.error(err)
                raise
        elif reqresp.status_code in [302, 303]:  # redirect
            return reqresp
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ParseError("ERROR: Something went wrong: %s" % reqresp.text)
        elif 400 <= reqresp.status_code < 500:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            # expecting an error response
            _deser_method = get_deserialization_method(reqresp)

            try:
                err_resp = service.parse_error_mesg(reqresp.text, _deser_method)
            except OicCliError:
                if _deser_method != response_body_type:
                    try:
                        err_resp = service.parse_error_mesg(reqresp.text,
                                                            response_body_type)
                    except OicCliError:
                        raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                            reqresp.text, reqresp.status_code, reqresp.url))
                else:
                    raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                        reqresp.text, reqresp.status_code, reqresp.url))

            return err_resp
        else:
            logger.error('Error response ({}): {}'.format(reqresp.status_code,
                                                          reqresp.text))
            raise cherrypy.HTTPError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))
