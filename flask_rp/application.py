import os

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from flask.app import Flask
from oidcop.utils import load_yaml_config

from oidcrp import RPHandler

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    oidc_keys_conf = app.config.get('OIDC_KEYS')
    verify_ssl = app.config.get('VERIFY_SSL')

    if oidc_keys_conf:
        _kj = init_key_jar(**oidc_keys_conf)
        _path = oidc_keys_conf['public_path']
        if _path.startswith('./'):
            _path = _path[2:]
        elif _path.startswith('/'):
            _path = _path[1:]
    else:
        _kj = KeyJar()
        _path = ''
    _kj.verify_ssl = verify_ssl

    rph = RPHandler(base_url=app.config.get('BASEURL'), hash_seed="BabyHoldOn",
                    keyjar=_kj, jwks_path=_path,
                    client_configs=app.config.get('CLIENTS'),
                    services=app.config.get('SERVICES'),
                    verify_ssl=verify_ssl)
    return rph


def oidc_provider_init_app(config_file, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    if config_file.endswith('.yaml'):
        app.config.update(load_yaml_config(config_file))
    elif config_file.endswith('.py'):
        app.config.from_pyfile(os.path.join(dir_path, config_file))
    else:
        raise ValueError('Unknown configuration format')

    app.config['SECRET_KEY'] = os.urandom(12).hex()

    app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.rph = init_oidc_rp_handler(app)

    return app
