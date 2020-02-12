"""Configuration management for RP"""

from typing import Dict

from oidcrp.logging import configure_logging
from oidcrp.util import get_http_params
from oidcrp.util import load_yaml_config
from oidcrp.util import lower_or_upper

try:
    from secrets import token_urlsafe as rnd_token
except ImportError:
    from oidcendpoint import rndstr as rnd_token


class Configuration:
    """RP Configuration"""

    def __init__(self, conf: Dict) -> None:
        self.logger = configure_logging(config=conf.get('logging')).getChild(__name__)

        # server info
        self.domain = lower_or_upper(conf, "domain")
        self.port = lower_or_upper(conf, "port")
        for param in ["server_name", "base_url"]:
            _pre = lower_or_upper(conf, param)
            if _pre:
                if '{domain}' in _pre:
                    setattr(self, param, _pre.format(domain=self.domain, port=self.port))
                else:
                    setattr(self, param, _pre)

        # HTTP params
        _params = get_http_params(conf.get("http_params"))
        if _params:
            self.httpc_params = _params
        else:
            _params = {'verify', lower_or_upper(conf, "verify_ssl", True)}

        self.web_conf = lower_or_upper(conf, "webserver")

        # diverse
        for param in ["html_home", "session_cookie_name", "preferred_url_scheme",
                      "services", "federation"]:
            setattr(self, param, lower_or_upper(conf, param))

        rp_keys_conf = lower_or_upper(conf, 'rp_keys')
        if rp_keys_conf is None:
            rp_keys_conf = lower_or_upper(conf, 'oidc_keys')
        setattr(self, "rp_keys", rp_keys_conf)

        _clients = lower_or_upper(conf, "clients")
        for key, spec in _clients.items():
            if key == "":
                continue
            if not spec.get("redirect_uris"):
                continue

            _redirects = []
            for _r in spec["redirect_uris"]:
                if '{domain}' in _r:
                    _redirects.append(_r.format(domain=self.domain, port=self.port))
                else:
                    _redirects.append(_r)
            spec["redirect_uris"] = _redirects

        setattr(self, "clients", _clients)

        hash_seed = lower_or_upper(conf, 'hash_seed')
        if not hash_seed:
            hash_seed = rnd_token(32)
        setattr(self, "hash_seed", hash_seed)

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
