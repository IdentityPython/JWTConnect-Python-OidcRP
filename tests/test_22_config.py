import os

from oidcmsg.configure import create_from_config_file

from oidcrp.configure import Configuration
from oidcrp.configure import RPConfiguration

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_yaml_config():
    c = create_from_config_file(Configuration,
                                entity_conf=[{"class": RPConfiguration, "attr": "rp"}],
                                filename=os.path.join(_dirname, 'conf.yaml'),
                                base_path=_dirname)
    assert c
    assert set(c.web_conf.keys()) == {'port', 'domain', 'server_cert', 'server_key', 'debug'}

    rp_config = c.rp
    assert rp_config.base_url == "https://127.0.0.1:8090"
    assert rp_config.httpc_params == {"verify": False}
    assert set(rp_config.services.keys()) == {'discovery', 'registration', 'authorization',
                                              'accesstoken', 'userinfo', 'end_session'}
    assert set(rp_config.clients.keys()) == {'', 'bobcat', 'flop'}


def test_dict():
    configuration = create_from_config_file(RPConfiguration,
                                            filename=os.path.join(_dirname, 'rp_conf.yaml'),
                                            base_path=_dirname)
    assert configuration

    assert configuration.base_url == "https://127.0.0.1:8090"
    assert configuration.httpc_params == {"verify": False}
    assert set(configuration.services.keys()) == {'discovery', 'registration', 'authorization',
                                                  'accesstoken', 'userinfo', 'end_session'}
    assert set(configuration.clients.keys()) == {'', 'bobcat', 'flop'}
