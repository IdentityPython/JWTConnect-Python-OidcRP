import os

from oidcrp.configure import Configuration
from oidcrp.configure import RPConfiguration
from oidcrp.configure import create_from_config_file

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_yaml_config():
    c = create_from_config_file(cls=Configuration, entity_conf_class=RPConfiguration,
                                filename=os.path.join(_dirname, 'conf.yaml'),
                                base_path=_dirname)
    assert c
    assert set(c.web_conf.keys()) == {'port', 'domain', 'server_cert', 'server_key', 'debug'}

    entity_config = c.entity
    assert entity_config.base_url == "https://127.0.0.1:8090"
    assert entity_config.httpc_params == {"verify": False}
    assert set(entity_config.services.keys()) == {'discovery', 'registration', 'authorization',
                                                  'accesstoken', 'userinfo', 'end_session'}
    assert set(entity_config.clients.keys()) == {'', 'bobcat', 'flop'}
