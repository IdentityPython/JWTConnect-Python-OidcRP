"""Configuration management for RP"""

from typing import Dict

from oidcrp.logging import configure_logging
from oidcrp.util import get_http_params
from oidcrp.util import load_yaml_config
from oidcrp.util import lower_or_upper
from oidcrp.util import replace
from oidcrp.util import set_param

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
        if self.port:
            format_args = {'domain': self.domain, 'port': self.port}
        else:
            format_args = {'domain': self.domain, "port": ""}

        for param in ["server_name", "base_url"]:
            set_param(self, conf, param, **format_args)

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
            set_param(self, conf, param)

        rp_keys_conf = lower_or_upper(conf, 'rp_keys')
        if rp_keys_conf is None:
            rp_keys_conf = lower_or_upper(conf, 'oidc_keys')
        setattr(self, "rp_keys", rp_keys_conf)

        _clients = lower_or_upper(conf, "clients")
        if _clients:
            for key, spec in _clients.items():
                if key == "":
                    continue
                # if not spec.get("redirect_uris"):
                #     continue

                for uri in ['redirect_uris', 'post_logout_redirect_uris', 'frontchannel_logout_uri',
                            'backchannel_logout_uri']:
                    replace(spec, uri, **format_args)

            setattr(self, "clients", _clients)

        hash_seed = lower_or_upper(conf, 'hash_seed')
        if not hash_seed:
            hash_seed = rnd_token(32)
        setattr(self, "hash_seed", hash_seed)
        self.load_extension(conf)

    def load_extension(self, conf):
        pass

    @classmethod
    def create_from_config_file(cls, filename: str):
        """Load configuration as YAML"""
        return cls(load_yaml_config(filename))
