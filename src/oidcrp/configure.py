"""Configuration management for RP"""
import importlib
import json
import logging
import os
from typing import Dict
from typing import List
from typing import Optional

from oidcmsg.configure import Base

from oidcrp.logging import configure_logging
from oidcrp.util import load_yaml_config
from oidcrp.util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from cryptojwt import rndstr as rnd_token

URIS = [
    "redirect_uris", 'post_logout_redirect_uris', 'frontchannel_logout_uri',
    'backchannel_logout_uri', 'issuer', 'base_url']


class RPConfiguration(Base):
    def __init__(self,
                 conf: Dict,
                 base_path: Optional[str] = '',
                 entity_conf: Optional[List[dict]] = None,
                 domain: Optional[str] = "127.0.0.1",
                 port: Optional[int] = 80,
                 file_attributes: Optional[List[str]] = None,
                 dir_attributes: Optional[List[str]] = None,
                 ):

        Base.__init__(self, conf,
                      base_path=base_path,
                      domain=domain,
                      port=port,
                      file_attributes=file_attributes,
                      dir_attributes=dir_attributes)

        self.key_conf = lower_or_upper(conf, 'rp_keys') or lower_or_upper(conf, 'oidc_keys')
        self.clients = lower_or_upper(conf, "clients")

        hash_seed = lower_or_upper(conf, 'hash_seed')
        if not hash_seed:
            hash_seed = rnd_token(32)
        self.hash_seed = hash_seed

        self.services = lower_or_upper(conf, "services")
        self.base_url = lower_or_upper(conf, "base_url")
        self.httpc_params = lower_or_upper(conf, "httpc_params", {"verify": True})

        if entity_conf:
            self.extend(entity_conf=entity_conf, conf=conf, base_path=base_path,
                        file_attributes=file_attributes, domain=domain, port=port)


class Configuration(Base):
    """RP Configuration"""

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 entity_conf: Optional[List[dict]] = None,
                 file_attributes: Optional[List[str]] = None,
                 domain: Optional[str] = "",
                 port: Optional[int] = 0,
                 dir_attributes: Optional[List[str]] = None,
                 ):
        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes,
                      dir_attributes=dir_attributes)

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcrp')

        self.web_conf = lower_or_upper(conf, "webserver")

        if entity_conf:
            self.extend(entity_conf=entity_conf, conf=conf, base_path=base_path,
                        file_attributes=file_attributes, domain=domain, port=port,
                        dir_attributes=dir_attributes)


# def create_from_config_file(cls,
#                             filename: str,
#                             base_path: Optional[str] = '',
#                             entity_conf: Optional[List[dict]] = None,
#                             file_attributes: Optional[List[str]] = None,
#                             dir_attributes: Optional[List[str]] = None,
#                             domain: Optional[str] = "",
#                             port: Optional[int] = 0):
#     if filename.endswith(".yaml"):
#         """Load configuration as YAML"""
#         _cnf = load_yaml_config(filename)
#     elif filename.endswith(".json"):
#         _str = open(filename).read()
#         _cnf = json.loads(_str)
#     elif filename.endswith(".py"):
#         head, tail = os.path.split(filename)
#         tail = tail[:-3]
#         module = importlib.import_module(tail)
#         _cnf = getattr(module, "CONFIG")
#     else:
#         raise ValueError("Unknown file type")
#
#     return cls(_cnf,
#                entity_conf=entity_conf,
#                base_path=base_path, file_attributes=file_attributes,
#                domain=domain, port=port, dir_attributes=dir_attributes)
