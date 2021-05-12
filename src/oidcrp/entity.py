from typing import Callable
from typing import Optional
from typing import Union

from cryptojwt import KeyJar

from oidcrp.client_auth import factory
from oidcrp.configure import Configuration
from oidcrp.service import init_services
from oidcrp.service_context import ServiceContext

DEFAULT_SERVICES = {
    "discovery": {
        'class': 'oidcrp.oauth2.provider_info_discovery.ProviderInfoDiscovery'
    },
    'authorization': {
        'class': 'oidcrp.oauth2.authorization.Authorization'
    },
    'access_token': {
        'class': 'oidcrp.oauth2.access_token.AccessToken'
    },
    'refresh_access_token': {
        'class': 'oidcrp.oauth2.refresh_access_token.RefreshAccessToken'
    }
}


class Entity():
    def __init__(self,
                 client_authn_factory: Optional[Callable] = None,
                 keyjar: Optional[KeyJar] = None,
                 config: Optional[Union[dict, Configuration]] = None,
                 services: Optional[dict] = None,
                 jwks_uri: Optional[str] = '',
                 httpc_params: Optional[dict] = None):

        if httpc_params:
            self.httpc_params = httpc_params
        else:
            self.httpc_params = {"verify": True}

        self._service_context = ServiceContext(keyjar=keyjar, config=config,
                                               jwks_uri=jwks_uri, httpc_params=self.httpc_params)

        _cid = self._service_context.get('client_id')
        if _cid:
            self.client_id = _cid

        _cam = client_authn_factory or factory

        _srvs = services or DEFAULT_SERVICES

        self._service = init_services(service_definitions=_srvs,
                                      client_get=self.client_get,
                                      client_authn_factory=_cam)

    def client_get(self, what, *arg):
        _func = getattr(self, "get_{}".format(what), None)
        if _func:
            return _func(*arg)
        return None

    def get_services(self, *arg):
        return self._service

    def get_service_context(self, *arg):
        return self._service_context

    def get_service(self, service_name, *arg):
        try:
            return self._service[service_name]
        except KeyError:
            return None

    def get_service_by_endpoint_name(self, endpoint_name, *arg):
        for service in self._service.values():
            if service.endpoint_name == endpoint_name:
                return service

        return None
