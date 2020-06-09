import os

from oidcrp.configure import Configuration

_dirname = os.path.dirname(os.path.abspath(__file__))


def test_yaml_config():
    c = Configuration.create_from_config_file(os.path.join(_dirname, 'conf.yaml'))
    assert c
    assert c.base_url == "https://127.0.0.1:8090"
    assert c.domain == "127.0.0.1"
    assert c.httpc_params == {"verify": False}
    assert c.port == 8090
    assert set(c.services.keys()) == {'discovery', 'registration', 'authorization', 'accesstoken',
                                      'userinfo', 'end_session'}
    assert c.web_conf == {
        'port': 8090, 'domain': '127.0.0.1', 'server_cert': 'certs/cert.pem',
        'server_key': 'certs/key.pem', 'debug': True
    }
    assert set(c.clients.keys()) == {'', 'bobcat', 'flop'}