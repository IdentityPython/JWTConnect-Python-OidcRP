import hashlib
import logging
import sys
import traceback
from importlib import import_module

from jwkest import as_bytes

from oiccli import oauth2
from oiccli import oic
from oiccli import rndstr
from oiccli.client_auth import CLIENT_AUTHN_METHOD
from oiccli.http import HTTPLib
from oiccli.webfinger import WebFinger

from oicmsg.oauth2 import ErrorResponse

from oicrp import provider

__author__ = 'Roland Hedberg'
__version__ = '0.0.1'

logger = logging.getLogger(__name__)


class HandlerError(Exception):
    pass


class ConfigurationError(Exception):
    pass


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
CLIENT_CONFIG = {}


class RPHandler(object):
    def __init__(self, base_url='', hash_seed="", keyjar=None, verify_ssl=False,
                 services=None, service_factory=None, client_configs=None,
                 client_authn_method=CLIENT_AUTHN_METHOD, client_cls=None,
                 **kwargs):
        self.base_url = base_url
        self.hash_seed = as_bytes(hash_seed)
        self.verify_ssl = verify_ssl
        self.keyjar = keyjar

        self.extra = kwargs

        self.client_cls = client_cls or oic.Client
        self.services = services
        self.service_factory = service_factory or factory
        self.client_authn_method = client_authn_method
        self.client_configs = client_configs

        # keep track on which RP instance that serves with OP
        self.issuer2rp = {}
        self.hash2issuer = {}

    def state2issuer(self, state):
        for iss, rp in self.issuer2rp.items():
            if state in rp.client_info.state_db:
                return iss

    def pick_config(self, issuer):
        try:
            return self.client_configs[issuer]
        except KeyError:
            return self.client_configs['']

    def load_provider_info(self, client, issuer):
        """
        If the provider info is statically provided not much has to be done.
        If it's expected to be gotten dynamically Provider Info discovery has
        to be performed.

        :param client: A :py:class:`oiccli.oic.Client` instance
        """
        try:
            _provider_info = client.client_info.config['provider_info']
        except KeyError:
            try:
                _srv = client.service['provider_info']
            except KeyError:
                raise ConfigurationError(
                    'Can not do dynamic provider info discovery')
            else:
                try:
                    _iss = client.client_info.config['srv_discovery_url']
                except KeyError:
                    _iss = issuer

                client.client_info.issuer = _iss
                _info = _srv.request_info(cli_info=client.client_info)
                _srv.service_request(url=_info['uri'],
                                     client_info=client.client_info)
        else:
            client.client_info.provider_info = _provider_info

    def load_registration_response(self, client):
        """
        If the client has been statically registered that information
        must be provided during the configuration. If expected to be
        done dynamically. This method will do dynamic client registration.

        :param client: A :py:class:òiccli.oic.Client` instance
        """
        try:
            _client_reg = client.client_info.config['registration_response']
        except KeyError:
            try:
                return client.do_request('registration')
            except KeyError:
                raise ConfigurationError('No registration info')
            except Exception as err:
                logger.error(err)
                raise
        else:
            client.client_info.registration_info = _client_reg

    def setup(self, issuer):
        """
        If no client exists for this issuer one is created and initiated with
        the necessary information for them to be able to communicate.

        :param issuer: The issuer ID
        :return: A :py:class:`oiccli.oic.Client` instance
        """
        try:
            client = self.issuer2rp[issuer]
        except KeyError:
            _cnf = self.pick_config(issuer)

            try:
                _services = _cnf['services']
            except KeyError:
                _services = self.services

            try:
                client = self.client_cls(
                    client_authn_method=self.client_authn_method,
                    verify_ssl=self.verify_ssl, services=_services,
                    service_factory=self.service_factory, config=_cnf)
            except Exception as err:
                logger.error('Failed initiating client: {}'.format(err))
                message = traceback.format_exception(*sys.exc_info())
                logger.error(message)
                raise

            client.client_info.base_url = self.base_url
            orig_issuer = issuer
            try:
                issuer = _cnf['issuer']
            except KeyError:
                pass

            if not client.client_info.provider_info:
                self.load_provider_info(client, issuer)
                issuer = client.client_info.provider_info['issuer']
            else:
                _pi = client.client_info.provider_info
                for endp in ['authorization_endpoint', 'token_endpoint',
                             'userinfo_endpoint']:
                    if endp in _pi:
                        for srv in client.service.values():
                            if srv.endpoint_name == endp:
                                srv.endpoint = _pi[endp]

            if not client.client_info.redirect_uris:
                # Create the necessary callback URLs
                callbacks = self.create_callbacks(issuer)
                logout_callback = self.base_url

                client.client_info.redirect_uris = list(callbacks.values())
                client.client_info.post_logout_redirect_uris = [logout_callback]
                client.client_info.callbacks = callbacks
            else:
                self.hash2issuer[orig_issuer] = issuer

            if not client.client_info.client_id:
                self.load_registration_response(client)

            self.issuer2rp[issuer] = client

        return client

    def create_callbacks(self, issuer):
        _hash = hashlib.sha256()
        _hash.update(self.hash_seed)
        _hash.update(as_bytes(issuer))
        _hex = _hash.hexdigest()
        self.hash2issuer[_hex] = issuer
        return {'code': "{}/authz_cb/{}".format(self.base_url, _hex),
                'implicit': "{}/authz_im_cb/{}".format(self.base_url, _hex)}

    @staticmethod
    def get_response_type(client, issuer):
        return client.client_info.behaviour['response_types'][0]

    @staticmethod
    def get_client_authn_method(client, endpoint):
        if endpoint == 'token_endpoint':
            try:
                am = client.client_info.behaviour['token_endpoint_auth_method']
            except KeyError:
                am = ''
            else:
                if isinstance(am, str):
                    return am
                else:
                    return am[0]

    # noinspection PyUnusedLocal
    def begin(self, issuer):
        """
        First make sure we have a client and that the client has
        the necessary information. Then construct and send an Authorization
        request. The response to that request will be sent to the callback
        URL.

        :param issuer: Issuer ID
        """

        # Get the client instance that has been assigned to this issuer
        client = self.setup(issuer)

        try:
            _cinfo = client.client_info

            _nonce = rndstr(24)
            request_args = {
                'redirect_uri': _cinfo.redirect_uris[0],
                'scope': _cinfo.behaviour['scope'],
                'response_type': _cinfo.behaviour['response_types'][0],
                'nonce': _nonce
            }
            _state = client.client_info.state_db.create_state(_cinfo.issuer,
                                                              request_args)
            request_args['state'] = _state
            client.client_info.state_db.bind_nonce_to_state(_nonce, _state)

            logger.debug('Authorization request args: {}'.format(request_args))

            _srv = client.service['authorization']
            _info = _srv.do_request_init(client.client_info,
                                         request_args=request_args)
            logger.debug('Authorization info: {}'.format(_info))
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise
        else:
            return _info['uri']

    def get_accesstoken(self, client, authresp):
        logger.debug('get_accesstoken')
        req_args = {
            'code': authresp['code'], 'state': authresp['state'],
            'redirect_uri': client.client_info.redirect_uris[0],
            'grant_type': 'authorization_code',
            'client_id': client.client_info.client_id,
            'client_secret': client.client_info.client_secret
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

        return tokenresp

    # # noinspection PyUnusedLocal
    # def verify_token(self, client, access_token):
    #     return {}

    def get_userinfo(self, client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        request_args = {'access_token': access_token}

        return client.do_request('userinfo', state=authresp["state"],
                                 request_args=request_args, **kwargs)

    def userinfo_in_id_token(self, id_token):
        """
        Weed out all claims that belong to the JWT
        """
        ui = id_token.extra()
        ui['sub'] = id_token['sub']
        return ui

    # noinspection PyUnusedLocal
    def phaseN(self, issuer, response):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved.

        :param issuer: Who sent the response
        :param response: The response in what ever format it was received
        """

        client = self.issuer2rp[issuer]

        _srv = client.service['authorization']
        try:
            authresp = _srv.parse_response(response, client.client_info,
                                           sformat='dict')
        except Exception as err:
            logger.error('Parsing authresp: {}'.format(err))
            raise
        else:
            logger.debug('Authz response: {}'.format(authresp.to_dict()))

        if isinstance(authresp, ErrorResponse):
            return False, authresp

        if client.client_info.state_db[authresp['state']]['as'] != issuer:
            logger.error('Issuer problem: {} != {}'.format(
                client.client_info.state_db[authresp['state']]['as'], issuer))
            # got it from the wrong bloke
            return False, 'Impersonator'

        client.client_info.state_db.add_response(authresp)

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
            if isinstance(token_resp, ErrorResponse):
                return False, "Invalid response %s." % token_resp["error"]

            client.client_info.state_db.add_response(
                token_resp, state=authresp['state'])
            access_token = token_resp["access_token"]
            id_token = token_resp['verified_id_token']

        if 'userinfo' in client.service and access_token:

            inforesp = self.get_userinfo(client, authresp, access_token)

            if isinstance(inforesp, ErrorResponse):
                return False, "Invalid response %s." % inforesp["error"]

        elif id_token:  # look for it in the ID Token
            inforesp = self.userinfo_in_id_token(id_token)
        else:
            inforesp = {}

        logger.debug("UserInfo: %s", inforesp)

        return True, inforesp, access_token, client

    # noinspection PyUnusedLocal
    def callback(self, query, hash):
        """
        This is where we come back after the OP has done the
        Authorization Request.

        :param query:
        :return:
        """

        try:
            assert self.state2issuer(query['state']) == self.hash2issuer[hash]
        except AssertionError:
            raise HandlerError('Got back state to wrong callback URL')
        except KeyError:
            raise HandlerError('Unknown state or callback URL')

        del self.hash2issuer[hash]

        try:
            client = self.issuer2rp[self.state2issuer(query['state'])]
        except KeyError:
            raise HandlerError('Unknown session')

        try:
            result = self.phaseN(client, query)
            logger.debug("phaseN response: {}".format(result))
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            raise HandlerError("An unknown exception has occurred.")

        return result

    def find_srv_discovery_url(self, resource):
        """
        Use Webfinger to find the OP, The input is a unique identifier
        of the user. Allowed forms are the acct, mail, http and https
        urls. If no protocol specification is given like if only an
        email like identifier is given. It will be translated if possible to
        one of the allowed formats.

        :param resource: unique identifier of the user.
        :return:
        """

        try:
            wf = WebFinger(httpd=HTTPLib(ca_certs=self.extra["ca_bundle"]))
        except KeyError:
            wf = WebFinger(httpd=HTTPLib(verify_ssl=False))

        return wf.discovery_query(resource)


def get_service_unique_request(service, request, **kwargs):
    """
    Get a class instance of a :py:class:`oiccli.request.Request` subclass
    specific to a specified service

    :param service: The name of the service
    :param request: The name of the request
    :param kwargs: Arguments provided when initiating the class
    :return: An initiated subclass of oiccli.request.Request or None if
        the service or the request could not be found.
    """
    if service in provider.__all__:
        mod = import_module('oicrp.provider.' + service)
        cls = getattr(mod, request)
        return cls(**kwargs)

    return None


def factory(req_name, **kwargs):
    if isinstance(req_name, tuple):
        if req_name[0] == 'oauth2':
            oauth2.service.factory(req_name[1], **kwargs)
        elif req_name[0] == 'oidc':
            oic.service.factory(req_name[1], **kwargs)
        else:
            return get_service_unique_request(req_name[0], req_name[1],
                                              **kwargs)
    else:
        return oic.service.factory(req_name, **kwargs)
