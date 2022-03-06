import logging
import sys
import traceback
from typing import Optional

from cryptojwt import as_unicode
from cryptojwt.key_bundle import keybundle_from_local_file
from cryptojwt.key_jar import init_key_jar
from cryptojwt.utils import as_bytes
from oidcmsg import verified_claim_name
from oidcmsg.client.exception import ConfigurationError
from oidcmsg.client.exception import OidcServiceError
from oidcmsg.exception import MessageException
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.exception import NotForMe
from oidcmsg.oauth2 import is_error_message
from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import AccessTokenResponse
from oidcmsg.oidc import AuthorizationRequest
from oidcmsg.oidc import AuthorizationResponse
from oidcmsg.oidc import Claims
from oidcmsg.oidc import OpenIDSchema
from oidcmsg.oidc import RegistrationRequest
from oidcmsg.oidc.session import BackChannelLogoutRequest
from oidcmsg.time_util import utc_time_sans_frac
from oidcmsg.util import add_path
from oidcmsg.util import rndstr

from oidcrp.defaults import DEFAULT_CLIENT_CONFIGS
from oidcrp.defaults import DEFAULT_OIDC_SERVICES
from oidcrp.defaults import DEFAULT_RP_KEY_DEFS
from . import oidc
from .oauth2 import Client
from .oauth2 import dynamic_provider_info_discovery
from .oauth2.utils import pick_redirect_uri

logger = logging.getLogger(__name__)


class RPHandler(object):
    def __init__(self, base_url, client_configs=None, services=None, keyjar=None,
                 hash_seed="", verify_ssl=True, client_authn_factory=None,
                 client_cls=None, state_db=None, http_lib=None, httpc_params=None,
                 **kwargs):

        self.base_url = base_url
        if hash_seed:
            self.hash_seed = as_bytes(hash_seed)
        else:
            self.hash_seed = as_bytes(rndstr(32))

        _jwks_path = kwargs.get('jwks_path')
        if keyjar is None:
            self.keyjar = init_key_jar(**DEFAULT_RP_KEY_DEFS, issuer_id='')
            self.keyjar.import_jwks_as_json(self.keyjar.export_jwks_as_json(True, ''), base_url)
            if _jwks_path is None:
                _jwks_path = DEFAULT_RP_KEY_DEFS['public_path']
        else:
            self.keyjar = keyjar

        if _jwks_path:
            self.jwks_uri = add_path(base_url, _jwks_path)
        else:
            self.jwks_uri = ""
            if len(self.keyjar):
                self.jwks = self.keyjar.export_jwks()
            else:
                self.jwks = {}

        if state_db:
            self.state_db = state_db
        else:
            self.state_db = {}

        self.extra = kwargs

        self.client_cls = client_cls or oidc.RP
        if services is None:
            self.services = DEFAULT_OIDC_SERVICES
        else:
            self.services = services

        self.client_authn_factory = client_authn_factory

        if client_configs is None:
            self.client_configs = DEFAULT_CLIENT_CONFIGS
        else:
            self.client_configs = client_configs

        # keep track on which RP instance that serves which OP
        self.issuer2rp = {}
        self.hash2issuer = {}
        self.httplib = http_lib

        if not httpc_params:
            self.httpc_params = {'verify': verify_ssl}
        else:
            self.httpc_params = httpc_params

        if not self.keyjar.httpc_params:
            self.keyjar.httpc_params = self.httpc_params

    def state2issuer(self, state):
        """
        Given the state value find the Issuer ID of the OP/AS that state value
        was used against.
        Will raise a KeyError if the state is unknown.

        :param state: The state value
        :return: An Issuer ID
        """
        for _rp in self.issuer2rp.values():
            try:
                _iss = _rp.client_get("service_context").state.get_iss(state)
            except KeyError:
                continue
            else:
                if _iss:
                    return _iss
        return None

    def pick_config(self, issuer):
        """
        From the set of client configurations pick one based on the issuer ID.
        Will raise a KeyError if issuer is unknown.

        :param issuer: Issuer ID
        :return: A client configuration
        """
        return self.client_configs[issuer]

    def get_session_information(self, key, client=None):
        """
        This is the second of the methods users of this class should know about.
        It will return the complete session information as an
        :py:class:`oidcrp.state_interface.State` instance.

        :param key: The session key (state)
        :return: A State instance
        """
        if not client:
            client = self.get_client_from_session_key(key)

        return client.client_get("service_context").state.get_state(key)

    def init_client(self, issuer):
        """
        Initiate a Client instance. Specifically which Client class is used
        is decided by configuration.

        :param issuer: An issuer ID
        :return: A Client instance
        """

        logger.debug(20 * "*" + " init_client " + 20 * "*")

        try:
            _cnf = self.pick_config(issuer)
        except KeyError:
            _cnf = self.pick_config('')
            _cnf['issuer'] = issuer

        try:
            _services = _cnf['services']
        except KeyError:
            _services = self.services

        try:
            client = self.client_cls(
                client_authn_factory=self.client_authn_factory,
                services=_services, config=_cnf, httplib=self.httplib,
                httpc_params=self.httpc_params)
        except Exception as err:
            logger.error('Failed initiating client: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise

        _context = client.client_get("service_context")
        # If non persistent
        _context.keyjar.load(self.keyjar.dump())
        # If persistent nothings has to be copied

        _context.base_url = self.base_url
        _context.jwks_uri = self.jwks_uri
        return client

    def do_provider_info(self,
                         client: Optional[Client] = None,
                         state: Optional[str] = '',
                         behaviour_args: Optional[dict] = None) -> str:
        """
        Either get the provider info from configuration or through dynamic
        discovery.

        :param behaviour_args:
        :param client: A Client instance
        :param state: A key by which the state of the session can be
            retrieved
        :return: issuer ID
        """
        logger.debug(20 * "*" + " do_provider_info " + 20 * "*")

        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        _context = client.client_get("service_context")
        if not _context.get('provider_info'):
            dynamic_provider_info_discovery(client, behaviour_args=behaviour_args)
            return _context.get('provider_info')['issuer']
        else:
            _pi = _context.get('provider_info')
            for key, val in _pi.items():
                # All service endpoint parameters in the provider info has
                # a name ending in '_endpoint' so I can look specifically
                # for those
                if key.endswith("_endpoint"):
                    for _srv in client.client_get("services").values():
                        # Every service has an endpoint_name assigned
                        # when initiated. This name *MUST* match the
                        # endpoint names used in the provider info
                        if _srv.endpoint_name == key:
                            _srv.endpoint = val

            if 'keys' in _pi:
                _kj = _context.keyjar
                for typ, _spec in _pi['keys'].items():
                    if typ == 'url':
                        for _iss, _url in _spec.items():
                            _kj.add_url(_iss, _url)
                    elif typ == 'file':
                        for kty, _name in _spec.items():
                            if kty == 'jwks':
                                _kj.import_jwks_from_file(_name, _context.get('issuer'))
                            elif kty == 'rsa':  # PEM file
                                _kb = keybundle_from_local_file(_name, "der", ["sig"])
                                _kj.add_kb(_context.get('issuer'), _kb)
                    else:
                        raise ValueError('Unknown provider JWKS type: {}'.format(typ))
            try:
                return _context.get('provider_info')['issuer']
            except KeyError:
                return _context.get('issuer')

    def do_client_registration(self, client=None,
                               iss_id: Optional[str] = '',
                               state: Optional[str] = '',
                               request_args: Optional[dict] = None,
                               behaviour_args: Optional[dict] = None):
        """
        Prepare for and do client registration if configured to do so

        :param iss_id: Issuer ID
        :param behaviour_args: To fine tune behaviour
        :param client: A Client instance
        :param state: A key by which the state of the session can be
            retrieved
        """

        logger.debug(20 * "*" + " do_client_registration " + 20 * "*")

        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        _context = client.client_get("service_context")
        _iss = _context.get('issuer')
        self.hash2issuer[iss_id] = _iss

        # This should only be interesting if the client supports Single Log Out
        # if _context.callback.get("post_logout_redirect_uri") is None:
        #     _context.callback["post_logout_redirect_uri"] = [self.base_url]

        if not client.get_client_id():  # means I have to do dynamic client registration
            if request_args is None:
                request_args = {}

            if behaviour_args:
                _params = RegistrationRequest().parameters()
                request_args.update({k: v for k, v in behaviour_args.items() if k in _params})

            load_registration_response(client, request_args=request_args)

    def do_webfinger(self, user: str) -> Client:
        """
        Does OpenID Provider Issuer discovery using webfinger.

        :param user: Identifier for the target End-User that is the subject of the discovery
            request.
        :return: A Client instance
        """

        logger.debug(20 * "*" + " do_webfinger " + 20 * "*")

        temporary_client = self.init_client('')
        temporary_client.do_request('webfinger', resource=user)
        return temporary_client

    def client_setup(self,
                     iss_id: Optional[str] = '',
                     user: Optional[str] = '',
                     behaviour_args: Optional[dict] = None) -> Client:
        """
        First if no issuer ID is given then the identifier for the user is
        used by the webfinger service to try to find the issuer ID.
        Once the method has an issuer ID if no client is bound to this issuer
        one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS that has the provided issuer ID.

        :param behaviour_args: To fine tune behaviour
        :param iss_id: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcrp.oidc.Client` instance
        """

        logger.debug(20 * "*" + " client_setup " + 20 * "*")

        logger.info('client_setup: iss_id={}, user={}'.format(iss_id, user))

        if not iss_id:
            if not user:
                raise ValueError('Need issuer or user')

            logger.debug("Connecting to previously unknown OP")
            temporary_client = self.do_webfinger(user)
        else:
            temporary_client = None

        try:
            client = self.issuer2rp[iss_id]
        except KeyError:
            if temporary_client:
                client = temporary_client
            else:
                logger.debug("Creating new client: %s", iss_id)
                client = self.init_client(iss_id)
        else:
            return client

        logger.debug("Get provider info")
        issuer = self.do_provider_info(client, behaviour_args=behaviour_args)

        logger.debug("Do client registration")
        self.do_client_registration(client, iss_id, behaviour_args=behaviour_args)

        self.issuer2rp[issuer] = client
        return client

    def _get_response_type(self, context, req_args: Optional[dict] = None):
        if req_args:
            return req_args.get("response_type", context.get('behaviour')['response_types'][0])
        else:
            return context.get('behaviour')['response_types'][0]

    def init_authorization(self,
                           client: Optional[Client] = None,
                           state: Optional[str] = '',
                           req_args: Optional[dict] = None,
                           behaviour_args: Optional[dict] = None) -> dict:
        """
        Constructs the URL that will redirect the user to the authorization
        endpoint of the OP/AS.

        :param behaviour_args:
        :param state:
        :param client: A Client instance
        :param req_args: Non-default Request arguments
        :return: A dictionary with 2 keys: **url** The authorization redirect
            URL and **state** the key to the session information in the
            state data store.
        """

        logger.debug(20 * "*" + " init_authorization " + 20 * "*")
        if not client:
            if state:
                client = self.get_client_from_session_key(state)
            else:
                raise ValueError('Missing state/session key')

        _context = client.client_get("service_context")

        _nonce = rndstr(24)
        _response_type = self._get_response_type(_context, req_args)
        request_args = {
            'redirect_uri': pick_redirect_uri(_context,
                                              request_args=req_args,
                                              response_type=_response_type),
            'scope': _context.get('behaviour')['scope'],
            'response_type': _response_type,
            'nonce': _nonce
        }

        _req_args = _context.config.get("request_args")
        if _req_args:
            if 'claims' in _req_args:
                _req_args["claims"] = Claims(**_req_args["claims"])
            request_args.update(_req_args)

        if req_args is not None:
            request_args.update(req_args)

        # Need a new state for a new authorization request
        _state = _context.state.create_state(_context.get('issuer'))
        request_args['state'] = _state
        _context.state.store_nonce2state(_nonce, _state)

        logger.debug('Authorization request args: {}'.format(request_args))

        # if behaviour_args and "request_param" not in behaviour_args:
        #     _pi = _context.get("provider_info")

        _srv = client.get_service('authorization')
        _info = _srv.get_request_parameters(request_args=request_args,
                                            behaviour_args=behaviour_args)
        logger.debug('Authorization info: {}'.format(_info))
        return {'url': _info['url'], 'state': _state}

    def begin(self, issuer_id='', user_id='', req_args=None, behaviour_args=None):
        """
        This is the first of the 3 high level methods that most users of this
        library should confine them self to use.
        If will use client_setup to produce a Client instance ready to be used
        against the OP/AS the user wants to use.
        Once it has the client it will construct an Authorization
        request.

        :param behaviour_args:
        :param req_args:
        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        :return: A dictionary containing **url** the URL that will redirect the
            user to the OP/AS and **state** the session key which will
            allow higher level code to access session information.
        """

        # Get the client instance that has been assigned to this issuer
        client = self.client_setup(issuer_id, user_id, behaviour_args=behaviour_args)

        try:
            res = self.init_authorization(client, req_args=req_args, behaviour_args=behaviour_args)
        except Exception:
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
        return client.service_context.get('behaviour')['response_types'][0]

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
                am = client.client_get("service_context").get('behaviour')[
                    'token_endpoint_auth_method']
            except KeyError:
                return ''
            else:
                if isinstance(am, str):
                    return am
                else:  # a list
                    return am[0]

    def get_tokens(self, state, client: Optional[Client] = None):
        """
        Use the 'accesstoken' service to get an access token from the OP/AS.

        :param state: The state key (the state parameter in the
            authorization request)
        :param client: A Client instance
        :return: A :py:class:`oidcmsg.oidc.AccessTokenResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse`
        """
        logger.debug(20 * "*" + " get_tokens " + 20 * "*")

        if client is None:
            client = self.get_client_from_session_key(state)

        _context = client.client_get("service_context")
        authorization_response = _context.state.get_item(AuthorizationResponse, 'auth_response',
                                                         state)
        authorization_request = _context.state.get_item(AuthorizationRequest, 'auth_request', state)

        req_args = {
            'code': authorization_response['code'],
            'state': state,
            'redirect_uri': authorization_request['redirect_uri'],
            'grant_type': 'authorization_code',
            'client_id': client.get_client_id(),
            'client_secret': _context.get('client_secret')
        }
        logger.debug('request_args: {}'.format(req_args))
        try:
            tokenresp = client.do_request(
                'accesstoken', request_args=req_args,
                authn_method=self.get_client_authn_method(client, "token_endpoint"),
                state=state
            )
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
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

        logger.debug(20 * "*" + " refresh_access_token " + 20 * "*")

        if scope:
            req_args = {'scope': scope}
        else:
            req_args = {}

        if client is None:
            client = self.get_client_from_session_key(state)

        try:
            tokenresp = client.do_request(
                'refresh_token',
                authn_method=self.get_client_authn_method(client, "token_endpoint"),
                state=state, request_args=req_args
            )
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
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

        logger.debug(20 * "*" + " get_user_info " + 20 * "*")

        if client is None:
            client = self.get_client_from_session_key(state)

        if not access_token:
            _arg = client.client_get("service_context").state.multiple_extend_request_args(
                {}, state, ['access_token'],
                ['auth_response', 'token_response', 'refresh_token_response'])

        request_args = {'access_token': access_token}

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
        res = dict([(k, id_token[k]) for k in OpenIDSchema.c_param.keys() if k in id_token])
        res.update(id_token.extra())
        return res

    def finalize_auth(self, client, issuer: str, response: dict,
                      behaviour_args: Optional[dict] = None):
        """
        Given the response returned to the redirect_uri, parse and verify it.

        :param behaviour_args: For fine tuning behaviour
        :param client: A Client instance
        :param issuer: An Issuer ID
        :param response: The authorization response as a dictionary
        :return: An :py:class:`oidcmsg.oidc.AuthorizationResponse` or
            :py:class:`oidcmsg.oauth2.AuthorizationResponse` instance.
        """

        logger.debug(20 * "*" + " finalize_auth " + 20 * "*")

        _srv = client.get_service('authorization')
        try:
            authorization_response = _srv.parse_response(response, sformat='dict',
                                                         behaviour_args=behaviour_args)
        except Exception as err:
            logger.error('Parsing authorization_response: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            logger.debug('Authz response: {}'.format(authorization_response.to_dict()))

        if is_error_message(authorization_response):
            return authorization_response

        _context = client.client_get("service_context")
        try:
            _iss = _context.state.get_iss(authorization_response['state'])
        except KeyError:
            raise KeyError('Unknown state value')

        if _iss != issuer:
            logger.error('Issuer problem: {} != {}'.format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError('Impersonator {}'.format(issuer))

        _srv.update_service_context(authorization_response, key=authorization_response['state'])
        _context.state.store_item(authorization_response, "auth_response",
                                  authorization_response['state'])
        return authorization_response

    def get_access_and_id_token(self, authorization_response=None,
                                state: Optional[str] = '',
                                client: Optional[object] = None,
                                behaviour_args: Optional[dict] = None):
        """
        There are a number of services where access tokens and ID tokens can
        occur in the response. This method goes through the possible places
        based on the response_type the client uses.

        :param behaviour_args: For fine tuning behaviour
        :param authorization_response: The Authorization response
        :param state: The state key (the state parameter in the
            authorization request)
        :return: A dictionary with 2 keys: **access_token** with the access
            token as value and **id_token** with a verified ID Token if one
            was returned otherwise None.
        """

        logger.debug(20 * "*" + " get_access_and_id_token " + 20 * "*")

        if client is None:
            client = self.get_client_from_session_key(state)

        _context = client.client_get("service_context")

        if authorization_response is None:
            if state:
                authorization_response = _context.state.get_item(
                    AuthorizationResponse, 'auth_response', state)
            else:
                raise ValueError(
                    'One of authorization_response or state must be provided')

        if not state:
            state = authorization_response['state']

        authreq = _context.state.get_item(AuthorizationRequest, 'auth_request', state)
        _resp_type = set(authreq['response_type'])

        access_token = None
        id_token = None
        if _resp_type in [{'id_token'}, {'id_token', 'token'},
                          {'code', 'id_token', 'token'}]:
            id_token = authorization_response['__verified_id_token']

        if _resp_type in [{'token'}, {'id_token', 'token'}, {'code', 'token'},
                          {'code', 'id_token', 'token'}]:
            access_token = authorization_response["access_token"]
            if behaviour_args:
                if behaviour_args.get("collect_tokens", False):
                    # get what you can from the token endpoint
                    token_resp = self.get_tokens(state, client=client)
                    if is_error_message(token_resp):
                        return False, "Invalid response %s." % token_resp["error"]
                    # Now which access_token should I use
                    access_token = token_resp["access_token"]
                    # May or may not get an ID Token
                    id_token = token_resp.get('__verified_id_token')

        elif _resp_type in [{'code'}, {'code', 'id_token'}]:
            # get the access token
            token_resp = self.get_tokens(state, client=client)
            if is_error_message(token_resp):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]
            # May or may not get an ID Token
            id_token = token_resp.get('__verified_id_token')

        return {'access_token': access_token, 'id_token': id_token}

    # noinspection PyUnusedLocal
    def finalize(self, issuer, response, behaviour_args: Optional[dict] = None):
        """
        The third of the high level methods that a user of this Class should
        know about.
        Once the consumer has redirected the user back to the
        callback URL there might be a number of services that the client should
        use. Which one those are are defined by the client configuration.

        :param behaviour_args: For fine tuning
        :param issuer: Who sent the response
        :param response: The Authorization response as a dictionary
        :returns: A dictionary with two claims:
            **state** The key under which the session information is
            stored in the data store and
            **error** and encountered error or
            **userinfo** The collected user information
        """

        client = self.issuer2rp[issuer]

        if behaviour_args:
            logger.debug(f"Finalize behaviour args: {behaviour_args}")

        authorization_response = self.finalize_auth(client, issuer, response)
        if is_error_message(authorization_response):
            return {
                'state': authorization_response['state'],
                'error': authorization_response['error']
            }

        _state = authorization_response['state']
        token = self.get_access_and_id_token(authorization_response, state=_state, client=client,
                                             behaviour_args=behaviour_args)
        _id_token = token.get("id_token")
        logger.debug(f"ID Token: {_id_token}")

        if client.client_get("service", "userinfo") and token['access_token']:
            inforesp = self.get_user_info(
                state=authorization_response['state'], client=client,
                access_token=token['access_token'])

            if isinstance(inforesp, ResponseMessage) and 'error' in inforesp:
                return {
                    'error': "Invalid response %s." % inforesp["error"],
                    'state': _state
                }

        elif _id_token:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(_id_token)
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        _context = client.client_get("service_context")
        try:
            _sid_support = _context.get('provider_info')['backchannel_logout_session_supported']
        except KeyError:
            try:
                _sid_support = _context.get('provider_info')[
                    'frontchannel_logout_session_supported']
            except:
                _sid_support = False

        if _sid_support and _id_token:
            try:
                sid = _id_token['sid']
            except KeyError:
                pass
            else:
                _context.state.store_sid2state(sid, _state)

        if _id_token:
            _context.state.store_sub2state(_id_token['sub'], _state)
        else:
            _context.state.store_sub2state(inforesp['sub'], _state)

        return {
            'userinfo': inforesp,
            'state': authorization_response['state'],
            'token': token['access_token'],
            'id_token': _id_token,
            'session_state': authorization_response.get('session_state', '')
        }

    def has_active_authentication(self, state):
        """
        Find out if the user has an active authentication

        :param state:
        :return: True/False
        """

        client = self.get_client_from_session_key(state)

        # Look for Id Token in all the places where it can be
        _arg = client.client_get("service_context").state.multiple_extend_request_args(
            {}, state, ['__verified_id_token'],
            ['auth_response', 'token_response', 'refresh_token_response'])

        if _arg:
            _now = utc_time_sans_frac()
            exp = _arg['__verified_id_token']['exp']
            return _now < exp
        else:
            return False

    def get_valid_access_token(self, state):
        """
        Find a valid access token.

        :param state:
        :return: An access token if a valid one exists and when it
            expires. Otherwise raise exception.
        """

        exp = 0
        token = None
        indefinite = []
        now = utc_time_sans_frac()

        client = self.get_client_from_session_key(state)
        _context = client.client_get("service_context")
        for cls, typ in [(AccessTokenResponse, 'refresh_token_response'),
                         (AccessTokenResponse, 'token_response'),
                         (AuthorizationResponse, 'auth_response')]:
            try:
                response = _context.state.get_item(cls, typ, state)
            except KeyError:
                pass
            else:
                if 'access_token' in response:
                    access_token = response["access_token"]
                    try:
                        _exp = response['__expires_at']
                    except KeyError:  # No expiry date, lives for ever
                        indefinite.append((access_token, 0))
                    else:
                        if _exp > now and _exp > exp:  # expires sometime in the future
                            exp = _exp
                            token = (access_token, _exp)

        if indefinite:
            return indefinite[0]
        else:
            if token:
                return token
            else:
                raise OidcServiceError('No valid access token')

    def logout(self, state: str,
               client: Optional[Client] = None,
               post_logout_redirect_uri: Optional[str] = '') -> dict:
        """
        Does a RP initiated logout from an OP. After logout the user will be
        redirect by the OP to a URL of choice (post_logout_redirect_uri).

        :param state: Key to an active session
        :param client: Which client to use
        :param post_logout_redirect_uri: If a special post_logout_redirect_uri
            should be used
        :return: A US
        """

        logger.debug(20 * "*" + " logout " + 20 * "*")

        if client is None:
            client = self.get_client_from_session_key(state)

        try:
            srv = client.client_get('service', 'end_session')
        except KeyError:
            raise OidcServiceError("Does not know how to logout")

        if post_logout_redirect_uri:
            request_args = {
                "post_logout_redirect_uri": post_logout_redirect_uri
            }
        else:
            request_args = {}

        resp = srv.get_request_parameters(state=state,
                                          request_args=request_args)

        logger.debug(f"EndSession Request: {resp}")
        return resp

    def close(self, state: str,
              issuer: Optional[str] = '',
              post_logout_redirect_uri: Optional[str] = '') -> dict:

        logger.debug(20 * "*" + " close " + 20 * "*")

        if issuer:
            client = self.issuer2rp[issuer]
        else:
            client = self.get_client_from_session_key(state)

        return self.logout(state=state, client=client,
                           post_logout_redirect_uri=post_logout_redirect_uri)

    def clear_session(self, state):
        client = self.get_client_from_session_key(state)
        client.client_get("service_context").state.remove_state(state)


def backchannel_logout(client, request='', request_args=None):
    """

    :param request: URL encoded logout request
    :return:
    """
    if request:
        req = BackChannelLogoutRequest().from_urlencoded(as_unicode(request))
    elif request_args:
        req = BackChannelLogoutRequest(**request_args)
    else:
        raise MissingRequiredAttribute('logout_token')

    _context = client.client_get("service_context")
    kwargs = {
        'aud': client.get_client_id(),
        'iss': _context.get('issuer'),
        'keyjar': _context.keyjar,
        'allowed_sign_alg': _context.get('registration_response').get(
            "id_token_signed_response_alg", "RS256")
    }

    logger.debug(f"(backchannel_logout) Verifying request using: {kwargs}")
    try:
        req.verify(**kwargs)
    except (MessageException, ValueError, NotForMe) as err:
        raise MessageException('Bogus logout request: {}'.format(err))
    else:
        logger.debug("Request verified OK")

    # Find the subject through 'sid' or 'sub'
    sub = req[verified_claim_name('logout_token')].get('sub')
    sid = None
    if not sub:
        sid = req[verified_claim_name('logout_token')].get('sid')

    if not sub and not sid:
        raise MessageException('Neither "sid" nor "sub"')
    elif sub:
        _state = _context.state.get_state_by_sub(sub)
    elif sid:
        _state = _context.state.get_state_by_sid(sid)
    else:
        _state = None

    return _state


def load_registration_response(client, request_args=None):
    """
    If the client has been statically registered that information
    must be provided during the configuration. If expected to be
    done dynamically this method will do dynamic client registration.

    :param client: A :py:class:`oidcmsg.client.oidc.Client` instance
    """
    if not client.client_get("service_context").get('client_id'):
        try:
            response = client.do_request('registration', request_args=request_args)
        except KeyError:
            raise ConfigurationError('No registration info')
        except Exception as err:
            logger.error(err)
            raise
        else:
            if 'error' in response:
                raise OidcServiceError(response.to_json())
