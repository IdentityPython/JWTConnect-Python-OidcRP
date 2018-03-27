import hashlib
import logging
import sys
import traceback
from importlib import import_module

from cryptojwt import as_bytes

from oidcmsg.oauth2 import ResponseMessage
from oidcmsg.oidc import OpenIDSchema

from oidcservice import rndstr
from oidcservice.client_auth import CLIENT_AUTHN_METHOD
from oidcservice.exception import OidcServiceError
from oidcservice.state_interface import StateInterface
from oidcservice.util import add_path

from oidcrp import provider
from oidcrp import oauth2
from oidcrp import oidc

__author__ = 'Roland Hedberg'
__version__ = '0.3.0'

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
            if response.is_error_message():
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
        if response.is_error_message():
            raise OidcServiceError(response['error'])


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=False,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_method=CLIENT_AUTHN_METHOD, client_cls=None,
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
        self.client_authn_method = client_authn_method
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
        return self.session_interface.get_iss(state)

    def pick_config(self, issuer):
        return self.client_configs[issuer]

    def init_client(self, issuer):
        _cnf = self.pick_config(issuer)

        try:
            _services = _cnf['services']
        except KeyError:
            _services = self.services

        try:
            client = self.client_cls(
                state_db=self.state_db,
                client_authn_method=self.client_authn_method,
                verify_ssl=self.verify_ssl, services=_services,
                service_factory=self.service_factory, config=_cnf)
        except Exception as err:
            logger.error('Failed initiating client: {}'.format(err))
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise

        client.service_context.base_url = self.base_url
        return client

    @staticmethod
    def do_provider_info(client):
        """
        Either get the provider info from configuration or from dynamic
        discovery

        :param client:
        :return: issuer ID
        """
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

    def do_client_registration(self, client):
        """
        Prepare for and do client registration if configured to do so

        :param client:
        :param issuer:
        :return:
        """

        _iss = client.service_context.issuer
        if not client.service_context.redirect_uris:
            # Create the necessary callback URLs
            # as a side effect self.hash2issuer is set
            callbacks = self.create_callbacks(_iss)

            client.service_context.redirect_uris = list(callbacks.values())
            client.service_context.callbacks = callbacks
        else:
            self.hash2issuer[_iss] = _iss

        # This should only be interesting if the client supports Single Log Out
        try:
            client.service_context.post_logout_redirect_uris
        except AttributeError:
            client.service_context.post_logout_redirect_uris = [self.base_url]

        if not client.service_context.client_id:
            load_registration_response(client)

    def client_setup(self, issuer='', user=''):
        """
        If no client exists for this issuer one is created and initiated with
        the necessary information for the client to be able to communicate
        with the OP/AS.

        :param issuer: The issuer ID
        :param user: A user identifier
        :return: A :py:class:`oidcservice.oidc.Client` instance
        """

        if not issuer:
            if not user:
                raise ValueError('Need issuer or user')

            temporary_client = self.init_client('')
            temporary_client.do_request('webfinger', resource=user)
            issuer = temporary_client.service_context.issuer
        else:
            temporary_client = None

        try:
            client = self.issuer2rp[issuer]
        except KeyError:
            if temporary_client:
                client = temporary_client
            else:
                client = self.init_client(issuer)
        else:
            return client

        issuer = self.do_provider_info(client)
        self.do_client_registration(client)
        self.issuer2rp[issuer] = client
        return client

    def create_callbacks(self, issuer):
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()
        self.hash2issuer[_hex] = issuer
        return {'code': "{}/authz_cb/{}".format(self.base_url, _hex),
                'implicit': "{}/authz_im_cb/{}".format(self.base_url, _hex),
                'form_post': "{}/authz_fp_cb/{}".format(self.base_url, _hex)}

    # noinspection PyUnusedLocal
    def begin(self, issuer_id='', user_id=''):
        """
        First make sure we have a client and that the client has
        the necessary information. Then construct and send an Authorization
        request. The response to that request will be sent to the callback
        URL.

        :param issuer_id: Issuer ID
        :param user_id: A user identifier
        """

        # Get the client instance that has been assigned to this issuer
        client = self.client_setup(issuer_id, user_id)

        try:
            _cinfo = client.service_context

            _nonce = rndstr(24)
            request_args = {
                'redirect_uri': _cinfo.redirect_uris[0],
                'scope': _cinfo.behaviour['scope'],
                'response_type': _cinfo.behaviour['response_types'][0],
                'nonce': _nonce
            }

            _state = self.session_interface.create_state(_cinfo.issuer)
            request_args['state'] = _state
            self.session_interface.store_nonce2state(_nonce, _state)

            logger.debug('Authorization request args: {}'.format(request_args))

            _srv = client.service['authorization']
            _info = _srv.get_request_parameters(client.service_context,
                                                request_args=request_args)
            logger.debug('Authorization info: {}'.format(_info))
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return {'url': _info['url'], 'session_key': _state}

    # ----------------------------------------------------------------------

    @staticmethod
    def get_response_type(client, issuer):
        return client.service_context.behaviour['response_types'][0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        if endpoint == 'token_endpoint':
            try:
                am = client.service_context.behaviour[
                    'token_endpoint_auth_method']
            except KeyError:
                am = ''
            else:
                if isinstance(am, str):
                    return am
                else:
                    return am[0]

    def get_accesstoken(self, client, authresp):
        logger.debug('get_accesstoken')
        req_args = {
            'code': authresp['code'], 'state': authresp['state'],
            'redirect_uri': client.service_context.redirect_uris[0],
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
                state=authresp['state']
            )
        except Exception as err:
            logger.error("%s", err)
            raise
        else:
            if tokenresp.is_error_message():
                raise OidcServiceError(tokenresp['error'])

        return tokenresp

    def get_userinfo(self, client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        request_args = {'access_token': access_token}

        resp = client.do_request('userinfo', state=authresp["state"],
                                 request_args=request_args, **kwargs)
        if resp.is_error_message():
            raise OidcServiceError(resp['error'])

    def userinfo_in_id_token(self, id_token):
        """
        Weed out all claims that belong to the JWT
        """
        res = dict([(k, id_token[k]) for k in OpenIDSchema.c_param.keys() if
                    k in id_token])
        res.update(id_token.extra())
        return res

    def finalize_auth(self, client, issuer, response):
        _srv = client.service['authorization']
        try:
            authresp = _srv.parse_response(response, client.service_context,
                                           sformat='dict')
        except Exception as err:
            logger.error('Parsing authresp: {}'.format(err))
            raise
        else:
            logger.debug('Authz response: {}'.format(authresp.to_dict()))

        if isinstance(authresp, ResponseMessage):
            return authresp

        try:
            _iss = self.session_interface.get_iss(authresp['state'])
        except KeyError:
            raise KeyError('Unknown state value')

        if _iss != issuer:
            logger.error('Issuer problem: {} != {}'.format(_iss, issuer))
            # got it from the wrong bloke
            raise ValueError('Impersonator {}'.format(issuer))
        return authresp

    def get_access_and_id_token(self, client, issuer, authresp):
        _resp_type = set(self.get_response_type(client, issuer).split(' '))

        access_token = None
        id_token = None
        if _resp_type in [{'id_token'}, {'id_token', 'token'},
                          {'code', 'id_token', 'token'}]:
            id_token = authresp['verified_id_token']

        if _resp_type in [{'token'}, {'id_token', 'token'}, {'code', 'token'},
                          {'code', 'id_token', 'token'}]:
            access_token = authresp["access_token"]
        elif _resp_type in [{'code'}, {'code', 'id_token'}]:
            # get the access token
            token_resp = self.get_accesstoken(client, authresp)
            if isinstance(token_resp, ResponseMessage):
                return False, "Invalid response %s." % token_resp["error"]

            access_token = token_resp["access_token"]

            try:
                id_token = token_resp['verified_id_token']
            except KeyError:
                pass

        return {'access_token': access_token, 'id_token': id_token}

    # noinspection PyUnusedLocal
    def finalize(self, issuer, response):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved.

        :param issuer: Who sent the response
        :param response: The response in what ever format it was received
        """

        client = self.issuer2rp[issuer]

        authresp = self.finalize_auth(client, issuer, response)
        if 'error' in authresp:
            return {'state': authresp['state'], 'error': authresp}

        token = self.get_access_and_id_token(client, issuer, authresp)

        if 'userinfo' in client.service and token['access_token']:

            inforesp = self.get_userinfo(client, authresp,
                                         token['access_token'])

            if isinstance(inforesp, ResponseMessage):
                return False, "Invalid response %s." % inforesp["error"]

        elif token['id_token']:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(token['id_token'])
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        return {'userinfo': inforesp, 'state': authresp['state']}


def get_service_unique_request(service, request, **kwargs):
    """
    Get a class instance of a :py:class:`oidcservice.request.Request` subclass
    specific to a specified service

    :param service: The name of the service
    :param request: The name of the request
    :param kwargs: Arguments provided when initiating the class
    :return: An initiated subclass of oidcservice.request.Request or None if
        the service or the request could not be found.
    """
    if service in provider.__all__:
        mod = import_module('oidcrp.provider.' + service)
        cls = getattr(mod, request)
        return cls(**kwargs)

    return None


def factory(req_name, **kwargs):
    if '.' in req_name:
        group, name = req_name.split('.')
        if group == 'oauth2':
            oauth2.service.factory(req_name[1], **kwargs)
        elif group == 'oidc':
            oidc.service.factory(req_name[1], **kwargs)
        else:
            return get_service_unique_request(group, name, **kwargs)
    else:
        return oidc.service.factory(req_name, **kwargs)
