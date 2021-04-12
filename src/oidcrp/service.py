""" The basic Service class upon which all the specific services are built. """
import logging
from typing import Callable
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cryptojwt.jwt import JWT
from cryptojwt.utils import qualified_name
from oidcmsg.impexp import ImpExp
from oidcmsg.item import DLDict
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oauth2 import is_error_message

from oidcrp import util
from oidcrp.client_auth import factory as ca_factory
from oidcrp.configure import Configuration
from oidcrp.exception import ResponseError
from oidcrp.util import JOSE_ENCODED
from oidcrp.util import JSON_ENCODED
from oidcrp.util import URL_ENCODED
from oidcrp.util import get_http_body
from oidcrp.util import get_http_url

__author__ = 'Roland Hedberg'

LOGGER = logging.getLogger(__name__)

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]

SPECIAL_ARGS = ['authn_endpoint', 'algs']

REQUEST_INFO = 'Doing request with: URL:{}, method:{}, data:{}, https_args:{}'


class Service(ImpExp):
    """The basic Service class."""
    msg_type = Message
    response_cls = Message
    error_msg = ResponseMessage
    endpoint_name = ''
    endpoint = ''
    service_name = ''
    synchronous = True
    default_authn_method = ''
    http_method = 'GET'
    request_body_type = 'urlencoded'
    response_body_type = 'json'

    parameter = {
        'default_authn_method': None,
        'endpoint': "",
        'error_msg': object,
        'http_method': None,
        'msg_type': object,
        'request_body_type': None,
        'response_body_type': None,
        'response_cls': object
    }

    init_args = ["client_get"]

    def __init__(self,
                 client_get: Callable,
                 conf: Optional[Union[dict, Configuration]] = None,
                 client_authn_factory: Optional[Callable] = None,
                 **kwargs):
        ImpExp.__init__(self)
        if client_authn_factory is None:
            self.client_authn_factory = ca_factory
        else:
            self.client_authn_factory = client_authn_factory

        self.client_get = client_get
        self.default_request_args = {}
        if conf:
            self.conf = conf
            for param in ['msg_type', 'response_cls', 'error_msg',
                          'default_authn_method', 'http_method',
                          'request_body_type', 'response_body_type']:
                if param in conf:
                    setattr(self, param, conf[param])
        else:
            self.conf = {}

        # pull in all the modifiers
        self.pre_construct = []
        self.post_construct = []
        self.construct_extra_headers = []

    def gather_request_args(self, **kwargs):
        """
        Go through the attributes that the message class can contain and
        add values if they are missing but exists in the client info or
        when there are default values.

        :param kwargs: Initial set of attributes.
        :return: Possibly augmented set of attributes
        """
        ar_args = kwargs.copy()

        _context = self.client_get("service_context")
        # Go through the list of claims defined for the message class
        # there are a couple of places where informtation can be found
        # access them in the order of priority
        # 1. A keyword argument
        # 2. configured set of default attribute values
        # 3. default attribute values defined in the OIDC standard document
        for prop in self.msg_type.c_param:
            if prop in ar_args:
                continue

            val = _context.get(prop)
            if not val:
                if "request_args" in self.conf:
                    val = self.conf['request_args'].get(prop)
                if not val:
                    val = _context.register_args.get(prop)
                    if not val:
                        val = self.default_request_args.get(prop)
                        if not val:
                            val = _context.behaviour.get(prop)

            if val:
                ar_args[prop] = val

        return ar_args

    def method_args(self, context, **kwargs):
        """
        Collect the set of arguments that should be used by a set of methods

        :param context: Which service we're working for
        :param kwargs: A set of keyword arguments that are added at run-time.
        :return: A set of keyword arguments
        """
        try:
            _args = self.conf[context].copy()
        except KeyError:
            _args = kwargs
        else:
            _args.update(kwargs)
        return _args

    def do_pre_construct(self, request_args, **kwargs):
        """
        Will run the pre_construct methods one by one in the order given.

        :param request_args: Request arguments
        :param kwargs: Extra key word arguments
        :return: A tuple of request_args and post_args. post_args are to be
            used by the post_construct methods.
        """

        _args = self.method_args('pre_construct', **kwargs)
        post_args = {}
        for meth in self.pre_construct:
            request_args, _post_args = meth(request_args, service=self, post_args=post_args,
                                            **_args)
            # Not necessarily independent
            # post_args.update(_post_args)

        return request_args, post_args

    def do_post_construct(self, request_args, **kwargs):
        """
        Will run the post_construct methods one at the time in order.

        :param request_args: Request arguments
        :param kwargs: Arguments used by the post_construct method
        :return: Possible modified set of request arguments.
        """
        _args = self.method_args('post_construct', **kwargs)

        for meth in self.post_construct:
            request_args = meth(request_args, service=self, **_args)

        return request_args

    def update_service_context(self, resp, key='', **kwargs):
        """
        A method run after the response has been parsed and verified.

        :param resp: The response as a :py:class:`oidcmsg.Message` instance
        :param key: The key under which the response should be stored
        :param kwargs: Extra key word arguments
        """
        pass

    def construct(self, request_args=None, **kwargs):
        """
        Instantiate the request as a message class instance with
        attribute values gathered in a pre_construct method or in the
        gather_request_args method.

        :param request_args:
        :param kwargs: extra keyword arguments
        :return: message class instance
        """
        if request_args is None:
            request_args = {}

        # run the pre_construct methods. Will return a possibly new
        # set of request arguments but also a set of arguments to
        # be used by the post_construct methods.
        request_args, post_args = self.do_pre_construct(request_args,
                                                        **kwargs)

        # If 'state' appears among the keyword argument and is not
        # expected to appear in the request, remove it.
        if 'state' in self.msg_type.c_param and 'state' in kwargs:
            # Don't overwrite something put there by the constructor
            if 'state' not in request_args:
                request_args['state'] = kwargs['state']

        # logger.debug("request_args: %s" % sanitize(request_args))
        _args = self.gather_request_args(**request_args)

        # logger.debug("kwargs: %s" % sanitize(kwargs))
        # initiate the request as in an instance of the self.msg_type
        # message type
        request = self.msg_type(**_args)

        return self.do_post_construct(request, **post_args)

    def init_authentication_method(self, request, authn_method,
                                   http_args=None, **kwargs):
        """
        Will run the proper client authentication method.
        Each such method will place the necessary information in the necessary
        place. A method may modify the request.

        :param request: The request, a Message class instance
        :param authn_method: Client authentication method
        :param http_args: HTTP header arguments
        :param kwargs: Extra keyword arguments
        :return: Extended set of HTTP header arguments
        """
        if http_args is None:
            http_args = {}

        if authn_method:
            LOGGER.debug('Client authn method: %s', authn_method)
            return self.client_authn_factory(authn_method).construct(
                request, self, http_args=http_args, **kwargs)

        return http_args

    def construct_request(self, request_args=None, **kwargs):
        """
        The method where everything is setup for sending the request.
        The request information is gathered and the where and how of sending the
        request is decided.

        :param request_args: Initial request arguments as a dictionary
        :param kwargs: Extra keyword arguments
        :return: A dictionary with the keys 'url' and possibly 'body', 'kwargs',
            'request' and 'ht_args'.
        """
        if request_args is None:
            request_args = {}

        return self.construct(request_args, **kwargs)

    def get_endpoint(self):
        """
        Find the service endpoint

        :return: The service endpoint (a URL)
        """
        if self.endpoint:
            return self.endpoint

        return self.client_get("service_context").provider_info[self.endpoint_name]

    def get_authn_header(self,
                         request: Union[dict, Message],
                         authn_method: Optional[str] = '',
                         **kwargs) -> dict:
        """
        Construct an authorization specification to be sent in the
        HTTP header.

        :param request: The service request
        :param authn_method: Which authentication/authorization method to use
        :param kwargs: Extra keyword arguments
        :return: A set of keyword arguments to be sent in the HTTP header.
        """
        headers = {}
        # If I should deal with client authentication
        if authn_method:
            h_arg = self.init_authentication_method(request, authn_method,
                                                    **kwargs)
            try:
                headers = h_arg['headers']
            except KeyError:
                pass

        return headers

    def get_authn_method(self) -> str:
        """
        Find the method that the client should use to authenticate against a
        service.

        :return: The authn/authz method
        """
        return self.default_authn_method

    def get_headers(self,
                    request: Union[dict, Message],
                    http_method: str,
                    authn_method: Optional[str] = '',
                    **kwargs) -> dict:
        """

        :param request:
        :param authn_method:
        :param kwargs:
        :return:
        """
        if not authn_method:
            authn_method = self.get_authn_method()

        _headers = self.get_authn_header(request,
                                         authn_method=authn_method,
                                         authn_endpoint=self.endpoint_name,
                                         **kwargs)

        for meth in self.construct_extra_headers:
            _headers = meth(self.client_get("service_context"),
                            headers=_headers,
                            request=request,
                            authn_method=authn_method,
                            service_endpoint=self.endpoint_name,
                            http_method=http_method,
                            **kwargs)

        return _headers

    def get_request_parameters(self, request_args=None, method="",
                               request_body_type="", authn_method='', **kwargs):
        """
        Builds the request message and constructs the HTTP headers.

        This is the starting point for a pipeline that will:

        - construct the request message
        - add/remove information to/from the request message in the way a
            specific client authentication method requires.
        - gather a set of HTTP headers like Content-type and Authorization.
        - serialize the request message into the necessary format (JSON,
            urlencoded, signed JWT)

        :param request_body_type: Which serialization to use for the HTTP body
        :param method: HTTP method used.
        :param authn_method: Client authentication method
        :param request_args: Message arguments
        :param kwargs: extra keyword arguments
        :return: Dictionary with the necessary information for the HTTP
            request
        """
        if not method:
            method = self.http_method
        if not authn_method:
            authn_method = self.get_authn_method()
        if not request_body_type:
            request_body_type = self.request_body_type

        request = self.construct_request(request_args=request_args, **kwargs)

        LOGGER.debug("Request: %s", request)
        _info = {'method': method, "request": request}

        _args = kwargs.copy()
        _context = self.client_get("service_context")
        if _context.issuer:
            _args['iss'] = _context.issuer

        # Client authentication by usage of the Authorization HTTP header
        # or by modifying the request object
        _headers = self.get_headers(request, http_method=method,
                                    authn_method=authn_method, **_args)

        # Find out where to send this request
        try:
            endpoint_url = kwargs['endpoint']
        except KeyError:
            endpoint_url = self.get_endpoint()

        _info['url'] = get_http_url(endpoint_url, request, method=method)

        # If there is to be a body part
        if method == 'POST':
            # How should it be serialized
            if request_body_type == 'urlencoded':
                content_type = URL_ENCODED
            elif request_body_type in ['jws', 'jwe', 'jose']:
                content_type = JOSE_ENCODED
            else:  # request_body_type == 'json'
                content_type = JSON_ENCODED

            _info['body'] = get_http_body(request, content_type)
            _headers.update({'Content-Type': content_type})

        if _headers:
            _info['headers'] = _headers

        return _info

    # ------------------ response handling -----------------------

    @staticmethod
    def get_urlinfo(info):
        """
        Pick out the fragment or query part from a URL.

        :param info: A URL possibly containing a query or a fragment part
        :return: the query/fragment part
        """
        # If info is a whole URL pick out the query or fragment part
        if '?' in info or '#' in info:
            parts = urlparse(info)
            # either query of fragment
            if parts.query:
                info = parts.query
            else:
                info = parts.fragment
        return info

    def post_parse_response(self, response, **kwargs):
        """
        This method does post processing of the service response.
        Each service have their own version of this method.

        :param response: The service response
        :param kwargs: A set of keyword arguments
        :return: The possibly modified response
        """
        return response

    def gather_verify_arguments(self):
        """
        Need to add some information before running verify()

        :return: dictionary with arguments to the verify call
        """

        _context = self.client_get("service_context")
        kwargs = {
            'iss': _context.issuer,
            'keyjar': _context.keyjar,
            'verify': True
        }

        _client_id = _context.client_id
        if _client_id:
            kwargs['client_id'] = _client_id

        if self.service_name == "provider_info":
            if _context.issuer.startswith("http://"):
                kwargs["allow_http"] = True

        return kwargs

    def _do_jwt(self, info):
        _context = self.client_get("service_context")
        args = {'allowed_sign_algs': _context.get_sign_alg(self.service_name)}
        enc_algs = _context.get_enc_alg_enc(self.service_name)
        args['allowed_enc_algs'] = enc_algs['alg']
        args['allowed_enc_encs'] = enc_algs['enc']
        _jwt = JWT(key_jar=_context.keyjar, **args)
        _jwt.iss = _context.client_id
        return _jwt.unpack(info)

    def _do_response(self, info, sformat, **kwargs):
        _context = self.client_get("service_context")

        try:
            resp = self.response_cls().deserialize(
                info, sformat, iss=_context.issuer, **kwargs)
        except Exception as err:
            resp = None
            if sformat == 'json':
                # Could be JWS or JWE but wrongly tagged
                # Adding issuer is just a fail-safe. If one things was wrong
                # then two can be.
                try:
                    resp = self.response_cls().deserialize(
                        info, 'jwt', iss=_context.issuer, **kwargs)
                except Exception:
                    pass

            if resp is None:
                LOGGER.error('Error while deserializing: %s', err)
                raise
        return resp

    def parse_response(self, info, sformat="", state="", **kwargs):
        """
        This the start of a pipeline that will:

            1 Deserializes a response into it's response message class.
              Or :py:class:`oidcmsg.oauth2.ErrorResponse` if it's an error
              message
            2 verifies the correctness of the response by running the
              verify method belonging to the message class used.
            3 runs the do_post_parse_response method iff the response was not
              an error response.

        :param info: The response, can be either in a JSON or an urlencoded
            format
        :param sformat: Which serialization that was used
        :param state: The state
        :param kwargs: Extra key word arguments
        :return: The parsed and to some extend verified response
        """

        if not sformat:
            sformat = self.response_body_type

        LOGGER.debug('response format: %s', sformat)

        if sformat in ['jose', 'jws', 'jwe']:
            resp = self.post_parse_response(info, state=state)

            if not resp:
                LOGGER.error('Missing or faulty response')
                raise ResponseError("Missing or faulty response")

            return resp

        # If format is urlencoded 'info' may be a URL
        # in which case I have to get at the query/fragment part
        if sformat == "urlencoded":
            info = self.get_urlinfo(info)

        if sformat == 'jwt':
            info = self._do_jwt(info)
            sformat = "dict"

        LOGGER.debug('response_cls: %s', self.response_cls.__name__)

        resp = self._do_response(info, sformat, **kwargs)

        LOGGER.debug('Initial response parsing => "%s"', resp.to_dict())

        # is this an error message
        if is_error_message(resp):
            LOGGER.debug('Error response: %s', resp)
        else:
            vargs = self.gather_verify_arguments()
            LOGGER.debug("Verify response with %s", vargs)
            try:
                # verify the message. If something is wrong an exception is
                # thrown
                resp.verify(**vargs)
            except Exception as err:
                LOGGER.error(
                    'Got exception while verifying response: %s', err)
                raise

            resp = self.post_parse_response(resp, state=state)

        if not resp:
            LOGGER.error('Missing or faulty response')
            raise ResponseError("Missing or faulty response")

        return resp

    def get_conf_attr(self, attr, default=None):
        """
        Get the value of a attribute in the configuration

        :param attr: The attribute
        :param default: If the attribute doesn't appear in the configuration
            return this value
        :return: The value of attribute in the configuration or the default
            value
        """
        if attr in self.conf:
            return self.conf[attr]

        return default


def gather_constructors(service_methods, construct):
    """Loads the construct methods that are defined."""
    try:
        _methods = service_methods
    except KeyError:
        pass
    else:
        for meth in _methods:
            try:
                func = meth['function']
            except KeyError:
                pass
            else:
                construct.append(util.importer(func))


def init_services(service_definitions, client_get, client_authn_factory=None):
    """
    Initiates a set of services

    :param service_definitions: A dictionary containing service definitions
    :param client_get: A function that returns different things from the base entity.
    :param client_authn_factory: A list of methods the services can use to
        authenticate the client to a service.
    :return: A dictionary, with service name as key and the service instance as
        value.
    """
    service = DLDict()
    for service_name, service_configuration in service_definitions.items():
        try:
            kwargs = service_configuration['kwargs']
        except KeyError:
            kwargs = {}

        kwargs.update({
            'client_get': client_get,
            'client_authn_factory': client_authn_factory
        })

        if isinstance(service_configuration['class'], str):
            _value_cls = service_configuration['class']
            _cls = util.importer(service_configuration['class'])
            _srv = _cls(**kwargs)
        else:
            _value_cls = qualified_name(service_configuration['class'])
            _srv = service_configuration['class'](**kwargs)

        if 'post_functions' in service_configuration:
            gather_constructors(service_configuration['post_functions'], _srv.post_construct)
        if 'pre_functions' in service_configuration:
            gather_constructors(service_configuration['pre_functions'], _srv.pre_construct)

        service[_srv.service_name] = _srv

    return service
