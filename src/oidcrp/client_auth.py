"""Implementation of a number of client authentication methods."""
import base64
import logging
from urllib.parse import quote_plus

from cryptojwt.exception import MissingKey
from cryptojwt.exception import UnsupportedAlgorithm
from cryptojwt.jws.jws import SIGNER_ALGS
from cryptojwt.jws.utils import alg2keytype
from oidcmsg.message import VREQUIRED
from oidcmsg.oauth2 import AccessTokenRequest
from oidcmsg.oauth2 import SINGLE_OPTIONAL_STRING
from oidcmsg.oidc import AuthnToken
from oidcmsg.time_util import utc_time_sans_frac

from oidcrp.util import rndstr
from oidcrp.util import sanitize
from .defaults import DEF_SIGN_ALG
from .defaults import JWT_BEARER

LOGGER = logging.getLogger(__name__)

__author__ = 'roland hedberg'


class AuthnFailure(Exception):
    """Unspecified Authentication failure"""


class UnknownAuthnMethod(Exception):
    """Unknown Authentication method."""


# ========================================================================
def assertion_jwt(client_id, keys, audience, algorithm, lifetime=600):
    """
    Create a signed Json Web Token containing some information.

    :param client_id: The Client ID
    :param keys: Signing keys
    :param audience: Who is the receivers for this assertion
    :param algorithm: Signing algorithm
    :param lifetime: The lifetime of the signed Json Web Token
    :return: A Signed Json Web Token
    """
    _now = utc_time_sans_frac()

    _token = AuthnToken(iss=client_id, sub=client_id,
                        aud=audience, jti=rndstr(32),
                        exp=_now + lifetime, iat=_now)
    LOGGER.debug('AuthnToken: %s', _token.to_dict())
    return _token.to_jwt(key=keys, algorithm=algorithm)


class ClientAuthnMethod:
    """
    Basic Client Authentication Method class.
    Only has one public method: *construct*
    """

    def construct(self, request, service=None, http_args=None, **kwargs):
        """ Add authentication information to a request"""
        raise NotImplementedError()

    def modify_request(self, request, service, **kwargs):
        """
        Modify the request if necessary.

        :param request: The request
        :param service: The service using this authentication method.
        """


class ClientSecretBasic(ClientAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server, may authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] using HTTP Basic authentication scheme.

    The upshot of this is to construct an Authorization header that has the
    value 'Basic <token>' where <token> is username and password concatenated
    together with a ':' in between and then URL safe base64 encoded.

    Note that both username and password
    """

    @staticmethod
    def _get_passwd(request, service, **kwargs):
        try:
            passwd = kwargs["password"]
        except KeyError:
            try:
                passwd = request["client_secret"]
            except KeyError:
                passwd = service.client_get("service_context").client_secret
        return passwd

    @staticmethod
    def _get_user(service, **kwargs):
        try:
            user = kwargs["user"]
        except KeyError:
            user = service.client_get("service_context").client_id
        return user

    def _get_authentication_token(self, request, service, **kwargs):
        """
        Return authentication Token.

        The credential is username and password concatenated with a ':'
        in between and then base 64 encoded becomes the authentication token.
        :param request: The request
        :param service: A :py:class:`oidcrp.service.Service` instance
        :param kwargs: Extra key word arguments
        :return: An authentication token
        """
        passwd = self._get_passwd(request, service, **kwargs)
        user = self._get_user(service, **kwargs)

        credentials = "{}:{}".format(quote_plus(user), quote_plus(passwd))
        return base64.urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")

    @staticmethod
    def _with_or_without_client_id(request, service):
        """ Add or delete client_id from request.

        If we're doing an access token request with an authorization code
        then we should add client_id to the request if it's not already there.
        :param request: A request
        :param service: A :py:class:`oidcrp.service.Service` instance
        """
        if isinstance(request, AccessTokenRequest) and request[
            'grant_type'] == 'authorization_code':
            if 'client_id' not in request:
                try:
                    request['client_id'] = service.client_get("service_context").client_id
                except AttributeError:
                    pass
        else:
            # remove client_id if not required by the request definition
            try:
                _req = request.c_param["client_id"][VREQUIRED]
            except (KeyError, AttributeError):
                _req = False

            # if it's not required remove it
            if not _req:
                try:
                    del request["client_id"]
                except KeyError:
                    pass

    def modify_request(self, request, service, **kwargs):
        """
        Modify the request if necessary.

        :param request: The request
        :param service: The service using this authentication method.
        """
        # If client_secret was part of the request message instance remove it
        try:
            del request["client_secret"]
        except (KeyError, TypeError):
            pass

        # Modifies the request
        self._with_or_without_client_id(request, service)

    def construct(self, request, service=None, http_args=None, **kwargs):
        """
        Construct a dictionary to be added to the HTTP request headers

        :param request: The request
        :param service: A :py:class:`oidcrp.service.Service` instance
        :param http_args: HTTP arguments
        :return: dictionary of HTTP arguments
        """

        if http_args is None:
            http_args = {}

        if "headers" not in http_args:
            http_args["headers"] = {}

        _token = self._get_authentication_token(request, service, **kwargs)

        http_args["headers"]["Authorization"] = "Basic {}".format(_token)

        self.modify_request(request, service)

        return http_args


class ClientSecretPost(ClientSecretBasic):
    """
    Clients that have received a client_secret value from the Authorization
    Server, authenticate with the Authorization Server in accordance with
    Section 3.2.1 of OAuth 2.0 [RFC6749] by including the Client Credentials in
    the request body.

    These means putting both client_secret and client_id in the request body.
    """

    def modify_request(self, request, service, **kwargs):
        """
        I MUST have a client_secret, there are 3 possible places
        where I can find it. In the request, as an argument in http_args
        or among the client information.

        :param request: The request
        :param service: The service that is using this authentication method
        """
        _context = service.client_get("service_context")
        if "client_secret" not in request:
            try:
                request["client_secret"] = kwargs["client_secret"]
            except (KeyError, TypeError):
                if _context.client_secret:
                    request["client_secret"] = _context.client_secret
                else:
                    raise AuthnFailure("Missing client secret")

        # Set the client_id in the the request
        request["client_id"] = _context.client_id

    def construct(self, request, service=None, http_args=None, **kwargs):
        """
        Does not add any authentication information to the HTTP arguments.
        Adds authentication information to the request.

        :param request: The request
        :param service: The service that is using this authentication method
        :param http_args: HTTP arguments
        :param kwargs: Extra keyword arguments.
        """
        self.modify_request(request, service, **kwargs)
        return http_args


def find_token(request, token_type, service, **kwargs):
    """
    The access token can be in a number of places.
    There are priority rules as to which one to use, abide by those:

    1 If it's among the request parameters use that
    2 If among the extra keyword arguments
    3 Acquired by a previous run service.

    :param request:
    :param token_type:
    :param service:
    :param kwargs:
    :return:
    """
    if request is not None:
        try:
            _token = request[token_type]
        except KeyError:
            pass
        else:
            del request[token_type]
            # Required under certain circumstances :-) not under other
            request.c_param[token_type] = SINGLE_OPTIONAL_STRING
            return _token

    try:
        return kwargs["access_token"]
    except KeyError:
        # I should pick the latest acquired token, this should be the right
        # order for that.
        _arg = service.client_get("service_context").state.multiple_extend_request_args(
            {}, kwargs['key'], ['access_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])
        return _arg['access_token']


class BearerHeader(ClientAuthnMethod):
    """The bearer header authentication method."""

    def construct(self, request=None, service=None, http_args=None,
                  **kwargs):
        """
        Constructing the Authorization header. The value of
        the Authorization header is "Bearer <access_token>".

        :param request: Request class instance
        :param service: Service
        :param http_args: HTTP header arguments
        :param kwargs: extra keyword arguments
        :return:
        """

        if service.service_name == 'refresh_token':
            _acc_token = find_token(request, 'refresh_token', service, **kwargs)
        else:
            _acc_token = find_token(request, 'access_token', service, **kwargs)

        if not _acc_token:
            raise KeyError('No access or refresh token available')

        # The authorization value starts with 'Bearer' when bearer tokens
        # are used
        _bearer = "Bearer {}".format(_acc_token)

        # Add 'Authorization' to the headers
        if http_args is None:
            http_args = {"headers": {}}
            http_args["headers"]["Authorization"] = _bearer
        else:
            try:
                http_args["headers"]["Authorization"] = _bearer
            except KeyError:
                http_args["headers"] = {"Authorization": _bearer}

        return http_args


class BearerBody(ClientAuthnMethod):
    """The bearer body authentication method."""

    def modify_request(self, request, service, **kwargs):
        """
        Modify the request if necessary.

        :param request: The request
        :param service: The service using this authentication method.
        :param kwargs: Extra keyword arguments
        """
        _acc_token = ''
        for _token_type in ['access_token', 'refresh_token']:
            _acc_token = find_token(request, _token_type, service, **kwargs)
            if _acc_token:
                break

        if not _acc_token:
            raise KeyError('No access or refresh token available')

        request["access_token"] = _acc_token

    def construct(self, request, service=None, http_args=None, **kwargs):
        """
        Will add a token to the request if not present

        :param request: The request
        :param service: The service that handles these kind of things.
        :param http_args: HTTP arguments
        :param kwargs: extra keyword arguments
        :return: A possibly modified dictionary with HTTP arguments.
        """

        self.modify_request(request, service, **kwargs)

        return http_args


def bearer_auth(request, authn):
    """
    Pick out the access token, either in HTTP_Authorization header or
    in request body.

    :param request: The request
    :param authn: The value of the Authorization header
    :return: An access token
    """

    try:
        return request["access_token"]
    except KeyError:
        if not authn.startswith("Bearer "):
            raise ValueError('Not a bearer token')
        return authn[7:]


class JWSAuthnMethod(ClientAuthnMethod):
    """
    Base class for client authentication methods that uses signed JSON
    Web Tokens.
    """

    @staticmethod
    def choose_algorithm(context, **kwargs):
        """
        Pick signing algorithm

        :param context: Signing context
        :param kwargs: extra keyword arguments
        :return: Name of a signing algorithm
        """
        try:
            algorithm = kwargs["algorithm"]
        except KeyError:
            # different contexts uses different signing algorithms
            algorithm = DEF_SIGN_ALG[context]
        if not algorithm:
            raise AuthnFailure("Missing algorithm specification")
        return algorithm

    @staticmethod
    def get_signing_key_from_keyjar(algorithm, service_context):
        """
        Pick signing key based on signing algorithm to be used

        :param algorithm: Signing algorithm
        :param service_context: A :py:class:`oidcrp.service_context.ServiceContext` instance
        :return: A key
        """
        return service_context.keyjar.get_signing_key(
            alg2keytype(algorithm), alg=algorithm)

    @staticmethod
    def _get_key_by_kid(kid, algorithm, service_context):
        """
        Pick a key that matches a given key ID and signing algorithm.

        :param kid: Key ID
        :param algorithm: Signing algorithm
        :param service_context: A
            :py:class:`oidcrp.service_context.ServiceContext` instance
        :return: A matching key
        """
        # signing so using my keys
        for _key in service_context.keyjar.get_issuer_keys(""):
            if kid == _key.kid:
                ktype = alg2keytype(algorithm)
                if _key.kty != ktype:
                    raise MissingKey("Wrong key type")

                return _key

        raise MissingKey("No key with kid:%s" % kid)

    def _get_signing_key(self, algorithm, context, kid=None):
        ktype = alg2keytype(algorithm)
        try:
            if kid:
                signing_key = [self._get_key_by_kid(kid, algorithm, context)]
            elif ktype in context.kid["sig"]:
                try:
                    signing_key = [self._get_key_by_kid(
                        context.kid["sig"][ktype], algorithm, context)]
                except KeyError:
                    signing_key = self.get_signing_key_from_keyjar(algorithm, context)
            else:
                signing_key = self.get_signing_key_from_keyjar(algorithm, context)
        except (MissingKey,) as err:
            LOGGER.error("%s", sanitize(err))
            raise

        return signing_key

    def _get_audience_and_algorithm(self, context, **kwargs):
        algorithm = None

        # audience for the signed JWT depends on which endpoint
        # we're talking to.
        if 'authn_endpoint' in kwargs and kwargs['authn_endpoint'] in ['token_endpoint']:
            reg_resp = context.registration_response
            if reg_resp:
                algorithm = reg_resp["token_endpoint_auth_signing_alg"]
            else:
                algorithm = context.client_preferences.get("token_endpoint_auth_signing_alg")
                if algorithm is None:
                    _pi = context.provider_info
                    try:
                        algs = _pi["token_endpoint_auth_signing_alg_values_supported"]
                    except KeyError:
                        algorithm = "RS256"  # default
                    else:
                        for alg in algs:  # pick the first one I support and have keys for
                            if alg in SIGNER_ALGS and self.get_signing_key_from_keyjar(alg,
                                                                                       context):
                                algorithm = alg
                                break

            audience = context.provider_info['token_endpoint']
        else:
            audience = context.provider_info['issuer']

        if not algorithm:
            algorithm = self.choose_algorithm(**kwargs)
        return audience, algorithm

    def _construct_client_assertion(self, service, **kwargs):
        _context = service.client_get("service_context")

        audience, algorithm = self._get_audience_and_algorithm(_context, **kwargs)

        if 'kid' in kwargs:
            signing_key = self._get_signing_key(algorithm, _context, kid=kwargs['kid'])
        else:
            signing_key = self._get_signing_key(algorithm, _context)

        if not signing_key:
            raise UnsupportedAlgorithm(algorithm)

        try:
            _args = {'lifetime': kwargs['lifetime']}
        except KeyError:
            _args = {}

        # construct the signed JWT with the assertions and add
        # it as value to the 'client_assertion' claim of the request
        return assertion_jwt(_context.client_id, signing_key, audience, algorithm, **_args)

    def modify_request(self, request, service, **kwargs):
        """
        Modify the request if necessary.

        :param request: The request
        :param service: The service using this authentication method.
        :param kwargs: Extra keyword arguments
        """
        if 'client_assertion' in kwargs:
            request["client_assertion"] = kwargs['client_assertion']
            if 'client_assertion_type' in kwargs:
                request[
                    'client_assertion_type'] = kwargs['client_assertion_type']
            else:
                request["client_assertion_type"] = JWT_BEARER
        elif 'client_assertion' in request:
            if 'client_assertion_type' not in request:
                request["client_assertion_type"] = JWT_BEARER
        else:
            request["client_assertion"] = self._construct_client_assertion(service, **kwargs)
            request["client_assertion_type"] = JWT_BEARER

        try:
            del request["client_secret"]
        except KeyError:
            pass

        # If client_id is not required to be present, remove it.
        if not request.c_param["client_id"][VREQUIRED]:
            try:
                del request["client_id"]
            except KeyError:
                pass

    def construct(self, request, service=None, http_args=None, **kwargs):
        """
        Constructs a client assertion and signs it with a key.
        The request is modified as a side effect.

        :param request: The request
        :param service: A :py:class:`oidcrp.service.Service` instance
        :param http_args: HTTP arguments
        :param kwargs: Extra arguments
        :return: Constructed HTTP arguments, in this case none
        """
        self.modify_request(request, service, **kwargs)

        return {}


class ClientSecretJWT(JWSAuthnMethod):
    """
    Clients that have received a client_secret value from the Authorization
    Server can create a signed JWT using an HMAC SHA algorithm, such as
    HMAC SHA-256.
    The HMAC (Hash-based Message Authentication Code) is calculated using the
    bytes of the UTF-8 representation of the client_secret as the shared key.
    """

    def choose_algorithm(self, context="client_secret_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(context, **kwargs)

    def get_signing_key_from_keyjar(self, algorithm, service_context):
        return service_context.keyjar.get_signing_key(alg2keytype(algorithm), alg=algorithm)


class PrivateKeyJWT(JWSAuthnMethod):
    """
    Clients that have registered a public key can sign a JWT using that key.
    """

    def choose_algorithm(self, context="private_key_jwt", **kwargs):
        return JWSAuthnMethod.choose_algorithm(context, **kwargs)

    def get_signing_key_from_keyjar(self, algorithm, service_context=None):
        return service_context.keyjar.get_signing_key(alg2keytype(algorithm), "", alg=algorithm)


# Map from client authentication identifiers to corresponding class
CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}

TYPE_METHOD = [(JWT_BEARER, JWSAuthnMethod)]


def valid_service_context(service_context, when=0):
    """
    Check if the client_secret has expired

    :param service_context: A
        :py:class:`oidcrp.service_context.ServiceContext` instance
    :param when: A time stamp against which the expiration time is to be checked
    :return: True if the client_secret is still valid
    """
    eta = service_context.client_secret_expires_at
    now = when or utc_time_sans_frac()
    if eta != 0 and eta < now:
        return False
    return True


def factory(auth_method):
    """Return an instance of a client authentication class.

    :param auth_method: The name of the client authentication method
    """
    try:
        return CLIENT_AUTHN_METHOD[auth_method]()
    except KeyError:
        LOGGER.error('Unknown client authentication method: %s', auth_method)
        raise ValueError(auth_method)
