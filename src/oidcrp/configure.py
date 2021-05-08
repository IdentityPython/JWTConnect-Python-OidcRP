"""Configuration management for RP"""
import importlib
import json
import logging
import os
from typing import Dict
from typing import List
from typing import Optional

from oidcrp.logging import configure_logging
from oidcrp.util import load_yaml_config
from oidcrp.util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcendpoint import rndstr as rnd_token

DEFAULT_FILE_ATTRIBUTE_NAMES = ['server_key', 'server_cert', 'filename', 'template_dir',
                                'private_path', 'public_path', 'db_file']


def add_base_path(conf: dict, base_path: str, file_attributes: List[str]):
    for key, val in conf.items():
        if key in file_attributes:
            if val.startswith("/"):
                continue
            elif val == "":
                conf[key] = "./" + val
            else:
                conf[key] = os.path.join(base_path, val)
        if isinstance(val, dict):
            conf[key] = add_base_path(val, base_path, file_attributes)

    return conf


def set_domain_and_port(conf: dict, uris: List[str], domain: str, port: int):
    for key, val in conf.items():
        if key in uris:
            if not val:
                continue

            if isinstance(val, list):
                _new = [v.format(domain=domain, port=port) for v in val]
            else:
                _new = val.format(domain=domain, port=port)
            conf[key] = _new
        elif isinstance(val, dict):
            conf[key] = set_domain_and_port(val, uris, domain, port)
    return conf


class Base:
    """ Configuration base class """

    def __init__(self,
                 conf: Dict,
                 base_path: str = '',
                 file_attributes: Optional[List[str]] = None,
                 ):

        if file_attributes is None:
            file_attributes = DEFAULT_FILE_ATTRIBUTE_NAMES

        if base_path and file_attributes:
            # this adds a base path to all paths in the configuration
            add_base_path(conf, base_path, file_attributes)

    def __getitem__(self, item):
        if item in self.__dict__:
            return self.__dict__[item]
        else:
            raise KeyError

    def get(self, item, default=None):
        return getattr(self, item, default)

    def __contains__(self, item):
        return item in self.__dict__

    def items(self):
        for key in self.__dict__:
            if key.startswith('__') and key.endswith('__'):
                continue
            yield key, getattr(self, key)

    def extend(self, entity_conf, conf, base_path, file_attributes, domain, port):
        for econf in entity_conf:
            _path = econf.get("path")
            _cnf = conf
            if _path:
                for step in _path:
                    _cnf = _cnf[step]
            _attr = econf["attr"]
            _cls = econf["class"]
            setattr(self, _attr,
                    _cls(_cnf, base_path=base_path, file_attributes=file_attributes,
                         domain=domain, port=port))


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
                 ):

        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes)

        _keys_conf = lower_or_upper(conf, 'rp_keys')
        if _keys_conf is None:
            _keys_conf = lower_or_upper(conf, 'oidc_keys')  # legacy

        self.keys = _keys_conf

        if not domain:
            domain = conf.get("domain", "127.0.0.1")

        if not port:
            port = conf.get("port", 80)

        conf = set_domain_and_port(conf, URIS, domain, port)
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
                 ):
        Base.__init__(self, conf, base_path=base_path, file_attributes=file_attributes)

        log_conf = conf.get('logging')
        if log_conf:
            self.logger = configure_logging(config=log_conf).getChild(__name__)
        else:
            self.logger = logging.getLogger('oidcrp')

        self.web_conf = lower_or_upper(conf, "webserver")

        # entity info
        if not domain:
            domain = conf.get("domain", "127.0.0.1")

        if not port:
            port = conf.get("port", 80)

        if entity_conf:
            self.extend(entity_conf=entity_conf, conf=conf, base_path=base_path,
                        file_attributes=file_attributes, domain=domain, port=port)


def create_from_config_file(cls,
                            filename: str,
                            base_path: Optional[str] = '',
                            entity_conf: Optional[List[dict]] = None,
                            file_attributes: Optional[List[str]] = None,
                            domain: Optional[str] = "",
                            port: Optional[int] = 0):
    if filename.endswith(".yaml"):
        """Load configuration as YAML"""
        _cnf = load_yaml_config(filename)
    elif filename.endswith(".json"):
        _str = open(filename).read()
        _cnf = json.loads(_str)
    elif filename.endswith(".py"):
        head, tail = os.path.split(filename)
        tail = tail[:-3]
        module = importlib.import_module(tail)
        _cnf = getattr(module, "CONFIG")
    else:
        raise ValueError("Unknown file type")

    return cls(_cnf,
               entity_conf=entity_conf,
               base_path=base_path, file_attributes=file_attributes,
               domain=domain, port=port)
