import hashlib
import logging
import sys
import traceback
from importlib import import_module

from cryptojwt import as_bytes
from oidcmsg.oauth2 import is_error_message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.time_util import time_sans_frac
from oidcservice import rndstr
from oidcservice.exception import OidcServiceError
from oidcservice.state_interface import StateInterface

from oidcrp import oauth2
from oidcrp import oidc
from oidcrp import provider

__author__ = 'Roland Hedberg'
__version__ = '0.4.8'

logger = logging.getLogger(__name__)

SUCCESSFUL = [200, 201, 202, 203, 204, 205, 206]


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


class HttpError(OidcServiceError):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}


class InMemoryStateDataBase(object):
    def __init__(self):
        self.db = {}

    def set(self, key, value):
        self.db[key] = value

    def get(self, key):
        try:
            return self.db[key]
        except KeyError:
            return None


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

    :param client: A :py:class:`oidcservice.oidc.Client` instance
    """
    try:
        _client_reg = client.service_context.config['registration_response']
    except KeyError:
        try:
            response = client.do_request('registration')
        except KeyError:
            raise ConfigurationError('No registration info')
        except Exception as err:
            logger.error(err)
            raise
        else:
            if 'error' in response:
                raise OidcServiceError(response['error'])
    else:
        client.service_context.registration_info = _client_reg


def dynamic_provider_info_discovery(client):
    """
    This is about performing dynamic Provider Info discovery

    :param client: A :py:class:`oidcservice.oidc.Client` instance
    """
    try:
        client.service['provider_info']
    except KeyError:
        raise ConfigurationError(
            'Can not do dynamic provider info discovery')
    else:
        try:
            client.service_context.issuer = client.service_context.config[
                'srv_discovery_url']
        except KeyError:
            pass

        response = client.do_request('provider_info')
        if is_error_message(response):
            raise OidcServiceError(response['error'])


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=True,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_factory=None, client_cls=None,
                 state_db=None, **kwargs):
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.verify_ssl = verify_ssl
        self.keyjar = keyjar

        if state_db:
            self.state_db = state_db
        else:
            self.state_db = InMemoryStateDataBase()

        self.session_interface = StateInterface(self.state_db)

        try:
            self.jwks_uri = add_path(base_url, kwargs['jwks_path'])
        except KeyError:
            pass

        self.extra = kwargs

        self.client_cls = client_cls or oidc.RP
        self.services = services
        self.service_factory = service_factory or factory
        self.client_authn_factory = client_authn_factory
        self.client_configs = client_configs

        # keep track on which RP instance that serves with OP
        self.issuer2rp = {}
        self.hash2issuer = {}

    def supports_webfinger(self):
        """
        WebFinger is only used when you don't know which OP/AS to talk to until
        a user gives you some information you can base a search on.

        :return: True if WebFinger is among the services supported.
        """
        _cnf = self.pick_config('')
        if 'WebFinger' in _cnf['services']:
            return True
        else:
            return False

    def state2issuer(self, state):
        """
        Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.

        :param state: The state value
        :return: An Issuer ID
        """
        return self.session_interface.get_iss(state)

    def pick_config(self, issuer):
        """
        From the set of client configurations pick one based on the issuer ID.
        Will raise a KeyError if issuer is unknown.

        :param issuer: Issuer ID
        :return: A client configuration
        """
        return self.client_configs[issuer]

    def get_session_information(self, key):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`oidcservice.state_interface.State` instance.

        :param key: The session key (state)
        :return: A State instance
        """
        return self.session_interface.get_state(key)

    def init_client(self, issuer):
        """
        Initiate a Client instance. Specifically which Client class is used
        is decided by configuration.

        :param issuer: An issuer ID
        :return: A Client instance
        """
        _cnf = self.pick_config(issuer)

        try:
            _services = _cnf['services']
        except KeyError:
            _services = self.services

        try:
            client = self.client_cls(
                state_db=self.state_db,
                client_authn_factory=self.client_authn_factory,
                verify_ssl=self.verify_ssl, services=_services,
                service_factory=self.service_factory, config=_cnf)
        except Exception as err:
            logger.error('Failed initiating client: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise

        client.service_context.base_url = self.base_url
        return client

    def do_provider_info(self, client=None, state=''):
        """
        Either get the provider info from configuration or through dynamic
        discovery.

        :param client: A Client instance
        :param state: A key by which the state of the session can be 
            retrieved 
        :return: issuer ID
        """

        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        if not client.service_context.provider_info:
            dynamic_provider_info_discovery(client)
            return client.service_context.provider_info['issuer']
        else:
            _pi = client.service_context.provider_info
            for endp in ['authorization_endpoint', 'token_endpoint',
                         'userinfo_endpoint']:
                if endp in _pi:
                    for srv in client.service.values():
                        if srv.endpoint_name == endp:
                            srv.endpoint = _pi[endp]
            try:
                return client.service_context.provider_info['issuer']
            except KeyError:
                return client.service_context.issuer

    def do_client_registration(self, client=None, iss_id='', state=''):
        """
        Prepare for and do client registration if configured to do so

        :param client: A Client instance
        :param state: A key by which the state of the session can be 
            retrieved 
        """

        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        _iss = client.service_context.issuer
        if not client.service_context.redirect_uris:
            # Create the necessary callback URLs
            # as a side effect self.hash2issuer is set
            callbacks = self.create_callbacks(_iss)

            client.service_context.redirect_uris = [
                v for k, v in callbacks.items() if not k.startswith('__')]
            client.service_context.callbacks = callbacks
        else:
            self.hash2issuer[iss_id] = _iss

        # This should only be interesting if the client supports Single Log Out
        try:
            client.service_context.post_logout_redirect_uris
        except AttributeError:
            client.service_context.post_logout_redirect_uris = [self.base_url]

        if not client.service_context.client_id:
            load_registration_response(client)

    def client_setup(self, iss_id='', user=''):
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcservice.oidc.Client` instance
        """

        logger.info('client_setup: iss_id={}, user={}'.format(iss_id, user))

        if not iss_id:
            if not user:
                raise ValueError('Need issuer or user')

            temporary_client = self.init_client('')
            temporary_client.do_request('webfinger', resource=user)
            issuer = temporary_client.service_context.issuer
        else:
            temporary_client = None

        try:
            client = self.issuer2rp[iss_id]
        except KeyError:
            if temporary_client:
                client = temporary_client
            else:
                client = self.init_client(iss_id)
        else:
            return client

        issuer = self.do_provider_info(client)
        self.do_client_registration(client, iss_id)
        self.issuer2rp[issuer] = client
        return client

    def create_callbacks(self, issuer):
        """
        To mitigate some security issues the redirect_uris should be OP/AS
        specific. This method creates a set of redirect_uris unique to the
        OP/AS.

        :param issuer: Issuer ID
        :return: A set of redirect_uris
        """
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()
        self.hash2issuer[_hex] = issuer
        return {
            'code': "{}/authz_cb/{}".format(self.base_url, _hex),
            'implicit': "{}/authz_im_cb/{}".format(self.base_url, _hex),
            'form_post': "{}/authz_fp_cb/{}".format(self.base_url, _hex),
            '__hex': _hex
        }

    def init_authorization(self, client=None, state='', req_args=None):
        """
        Constructs the URL that will redirect the user to the authorization
        endpoint of the OP/AS.

        :param client: A Client instance
        :param req_args: Non-default Request arguments
        :return: A dictionary with 2 keys: **url** The authorization redirect
            URL and **state** the key to the session information in the
            state data store.
        """
        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        service_context = client.service_context

        _nonce = rndstr(24)
        request_args = {
            'redirect_uri': service_context.redirect_uris[0],
            'scope': service_context.behaviour['scope'],
            'response_type': service_context.behaviour['response_types'][0],
            'nonce': _nonce
        }

        if req_args is not None:
            request_args.update(req_args)

        # Need a new state for a new authorization request
        _state = self.session_interface.create_state(service_context.issuer)
        request_args['state'] = _state
        self.session_interface.store_nonce2state(_nonce, _state)

        logger.debug('Authorization request args: {}'.format(request_args))

        _srv = client.service['authorization']
        _info = _srv.get_request_parameters(request_args=request_args)
        logger.debug('Authorization info: {}'.format(_info))
        return {'url': _info['url'], 'state': _state}

    def begin(self, issuer_id='', user_id=''):
        """
        This is the first of the 3 high level methods that most users of this
        library should confine them self to use.
        If will use client_setup to produce a Client instance ready to be used
        against the OP/AS the user wants to use.
        Once it has the client it will construct an Authorization
        request.

        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        :return: A dictionary containing **url** the URL that will redirect the
            user to the OP/AS and **state** the session key which will
            allow higher level code to access session information.
        """

        # Get the client instance that has been assigned to this issuer
        client = self.client_setup(issuer_id, user_id)

        try:
            res = self.init_authorization(client)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return res

    # ----------------------------------------------------------------------

    def get_client_from_session_key(self, state):
        return self.issuer2rp[self.state2issuer(state)]

    @staticmethod
    def get_response_type(client):
        """
        Return the response_type a specific client wants to use.

        :param client: A Client instance
        :return: The response_type
        """
        return client.service_context.behaviour['response_types'][0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        """
        Return the client authentication method a client wants to use a
        specific endpoint

        :param client: A Client instance
        :param endpoint: The endpoint at which the client has to authenticate
        :return: The client authentication method
        """
        if endpoint == 'token_endpoint':
            try:
                am = client.service_context.behaviour[
                    'token_endpoint_auth_method']
            except KeyError:
                return ''
            else:
                if isinstance(am, str):
                    return am
                else:  # a list
                    return am[0]

    def get_access_token(self, state, client=None):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :param client: A Client instance
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse`
        """
        logger.debug('get_accesstoken')

        if client is None:
            client = self.get_client_from_session_key(state)

        authorization_response = self.session_interface.get_item(
            AuthorizationResponse, 'auth_response', state)
        authorization_request = self.session_interface.get_item(
            AuthorizationRequest, 'auth_request', state)

        req_args = {
            'code': authorization_response['code'],
            'state': state,
            'redirect_uri': authorization_request['redirect_uri'],
            'grant_type': 'authorization_code',
            'client_id': client.service_context.client_id,
            'client_secret': client.service_context.client_secret
        }
        logger.debug('request_args: {}'.format(req_args))
        try:
            tokenresp = client.do_request(
                'accesstoken', request_args=req_args,
                authn_method=self.get_client_authn_method(client,
                                                          "token_endpoint"),
                state=state
            )
        except Exception as err:
            logger.error("%s", err)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp['error'])

        return tokenresp

    def refresh_access_token(self, state, client=None, scope=''):
        """
        Refresh an access token using a refresh_token. When asking for a new
        access token the RP can ask for another scope for the new token.

        :param client: A Client instance
        :param state: The state key (the state parameter in the
            authorization request)
        :param scope: What the returned token should be valid for.
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` instance
        """
        if scope:
            req_args = {'scope': scope}
        else:
            req_args = {}

        if client is None:
            client = self.get_client_from_session_key(state)

        try:
            tokenresp = client.do_request(
                'refresh_token',
                authn_method=self.get_client_authn_method(client,
                                                          "token_endpoint"),
                state=state, request_args=req_args
            )
        except Exception as err:
            logger.error("%s", err)
            raise
        else:
            if is_error_message(tokenresp):
                raise OidcServiceError(tokenresp['error'])

        return tokenresp

    def get_user_info(self, state, client=None, access_token='',
                      **kwargs):
        """
        use the access token previously acquired to get some userinfo

        :param client: A Client instance
        :param state: The state value, this is the key into the session
            data store
        :param access_token: An access token
        :param kwargs: Extra keyword arguments
        :return: A :py:class:`oidcmsg.oidc.OpenIDSchema` instance
        """
        if not access_token:
            _arg = self.session_interface.multiple_extend_request_args(
                {}, state, ['access_token'],
                ['auth_response', 'token_response', 'refresh_token_response'])

        request_args = {'access_token': access_token}

        if client is None:
            client = self.get_client_from_session_key(state)

        resp = client.do_request('userinfo', state=state,
                                 request_args=request_args, **kwargs)
        if is_error_message(resp):
            raise OidcServiceError(resp['error'])

        return resp

    @staticmethod
    def userinfo_in_id_token(id_token):
        """
        Given an verified ID token return all the claims that may been user
        information.

        :param id_token: An :py:class:`oidcmsg.oidc.IDToken` instance
        :return: A dictionary with user information
        """
        res = dict([(k, id_token[k]) for k in OpenIDSchema.c_param.keys() if
                    k in id_token])
        res.update(id_token.extra())
        return res

    def finalize_auth(self, client, issuer, response):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param client: A Client instance
        :param issuer: An Issuer ID
        :param response: The authorization response as a dictionary
        :return: An :py:class:`oidcmsg.oidc.AuthorizationResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse` instance.
        """
        _srv = client.service['authorization']
        try:
            authorization_response = _srv.parse_response(response,
                                                         sformat='dict')
        except Exception as err:
            logger.error('Parsing authorization_response: {}'.format(err))
            raise
        else:
            logger.debug(
                'Authz response: {}'.format(authorization_response.to_dict()))

        if is_error_message(authorization_response):
            return authorization_response

        try:
            _iss = self.session_interface.get_iss(
                authorization_response['state'])
        except KeyError:
            raise KeyError('Unknown state value')

        if _iss != issuer:
            logger.error('Issuer problem: {} != {}'.format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError('Impersonator {}'.format(issuer))

        _srv.update_service_context(authorization_response,
                                    state=authorization_response['state'])
        return authorization_response

    def get_access_and_id_token(self, authorization_response=None, state='',
                                client=None):
        """
        There are a number of services where access tokens and ID tokens can
        occur in the response. This method goes through the possible places
        based on the response_type the client uses.

        :param authorization_response: The Authorization response
        :param state: The state key (the state parameter in the
            authorization request)
        :return: A dictionary with 2 keys: **access_token** with the access
            token as value and **id_token** with a verified ID Token if one
            was returned otherwise None.
        """
        if authorization_response is None:
            if state:
                authorization_response = self.session_interface.get_item(
                    AuthorizationResponse, 'auth_response', state)
            else:
                raise ValueError(
                    'One of authorization_response or state must be provided')

        if not state:
            state = authorization_response['state']

        authreq = self.session_interface.get_item(
            AuthorizationRequest, 'auth_request', state)
        _resp_type = set(authreq['response_type'])

        access_token = None
        id_token = None
        if _resp_type in [{'id_token'}, {'id_token', 'token'},
                          {'code', 'id_token', 'token'}]:
            id_token = authorization_response['__verified_id_token']

        if _resp_type in [{'token'}, {'id_token', 'token'}, {'code', 'token'},
                          {'code', 'id_token', 'token'}]:
            access_token = authorization_response["access_token"]
        elif _resp_type in [{'code'}, {'code', 'id_token'}]:

            if client is None:
                client = self.get_client_from_session_key(state)

            # get the access token
            token_resp = self.get_access_token(state, client=client)
            if is_error_message(token_resp):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]

            try:
                id_token = token_resp['__verified_id_token']
            except KeyError:
                pass

        return {'access_token': access_token, 'id_token': id_token}

    # noinspection PyUnusedLocal
    def finalize(self, issuer, response):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are are defined by the client configuration.

        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with two claims:
            **state** The key under which the session information is
            stored in the data store and
            **error** and encountered error or
            **userinfo** The collected user information
        """

        client = self.issuer2rp[issuer]

        authorization_response = self.finalize_auth(client, issuer, response)
        if is_error_message(authorization_response):
            return {
                'state': authorization_response['state'],
                'error': authorization_response['error']
            }

        _state = authorization_response['state']
        token = self.get_access_and_id_token(authorization_response,
                                             state=_state, client=client)

        if 'userinfo' in client.service and token['access_token']:

            inforesp = self.get_user_info(
                state=authorization_response['state'], client=client,
                access_token=token['access_token'])

            if isinstance(inforesp, ResponseMessage) and 'error' in inforesp:
                return {
                    'error': "Invalid response %s." % inforesp["error"],
                    'state': _state
                }

        elif token['id_token']:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(token['id_token'])
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        return {
            'userinfo': inforesp,
            'state': authorization_response['state'],
            'token': token['access_token']
        }

    def has_active_authentication(self, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        # Look for Id Token in all the places where it can be
        _arg = self.session_interface.multiple_extend_request_args(
            {}, state, ['__verified_id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])

        if _arg:
            _now = time_sans_frac()
            exp = _arg['__verified_id_token']['exp']
            return _now < exp
        else:
            return False

    def get_valid_access_token(self, state):
        """
        Find me a valid access token

        :param state:
        :return: An access token if a valid one exists and when it
            expires. Otherwise raise exception.
        """

        exp = 0
        token = None
        indefinite = []
        now = time_sans_frac()

        for cls, typ in [(AccessTokenResponse, 'refresh_token_response'),
                         (AccessTokenResponse, 'token_response'),
                         (AuthorizationResponse, 'auth_response')]:
            try:
                response = self.session_interface.get_item(cls, typ, state)
            except KeyError:
                pass
            else:
                try:
                    access_token = response['access_token']
                except:
                    continue
                else:
                    try:
                        _exp = response['__expires_at']
                    except KeyError:  # No expiry date, lives for ever
                        indefinite.append((access_token, 0))
                    else:
                        if _exp > now:  # expires sometime in the future
                            if _exp > exp:
                                exp = _exp
                                token = (access_token, _exp)

        if indefinite:
            return indefinite[0]
        else:
            if token:
                return token
            else:
                raise OidcServiceError('No valid access token')


def get_provider_specific_service(service_provider, service, **kwargs):
    """
    Get a class instance of a :py:class:`oidcservice.service.Service` subclass
    specific to a specified service provider.

    :param service_provider: The name of the service provider
    :param service: The name of the service
    :param kwargs: Arguments provided when initiating the class
    :return: An initiated subclass of :py:class:`oidcservice.service.Service`
        or None if the service or the service provider could not be found.
    """
    if service_provider in provider.__all__:
        mod = import_module('oidcrp.provider.' + service_provider)
        cls = getattr(mod, service)
        return cls(**kwargs)

    return None


def factory(service_name, **kwargs):
    """
    A factory the given a service name will return a
    :py:class:`oidcservice.service.Service` instance if a service matching the
    name could be found.

    :param service_name: A service name, could be either of the format
        'group.name' or 'name'.
    :param kwargs: A set of key word arguments to be used when initiating the
        Service class
    :return: A :py:class:`oidcservice.service.Service` instance or None
    """
    if '.' in service_name:
        group, name = service_name.split('.')
        if group == 'oauth2':
            oauth2.service.factory(service_name[1], **kwargs)
        elif group == 'oidc':
            oidc.service.factory(service_name[1], **kwargs)
        else:
            return get_provider_specific_service(group, name, **kwargs)
    else:
        return oidc.service.factory(service_name, **kwargs)
