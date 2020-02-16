import os
import re

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from flask.app import Flask

from oidcrp import RPHandler
from oidcrp.util import load_yaml_config

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    verify_ssl = app.config.get('VERIFY_SSL')
    httpc_params = {"verify": verify_ssl}

    _cert = app.config.get("CLIENT_CERT")
    _key = app.config.get("CLIENT_KEY")
    if _cert and _key:
        httpc_params["cert"] = (_cert, _key)
    elif _cert:
        httpc_params["cert"] = _cert

    hash_seed = app.config.get('HASH_SEED')
    if not hash_seed:
        hash_seed = "BabyHoldOn"

    rp_keys_conf = app.config.get('RP_KEYS')
    if rp_keys_conf is None:
        rp_keys_conf = app.config.get('OIDC_KEYS')

    if rp_keys_conf:
        _kj = init_key_jar(**rp_keys_conf)
        _path = rp_keys_conf['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = httpc_params

    rph = RPHandler(base_url=app.config.get('BASEURL'),
                    hash_seed=hash_seed, keyjar=_kj, jwks_path=_path,
                    client_configs=app.config.get('CLIENTS'),
                    services=app.config.get('SERVICES'), httpc_params=httpc_params)

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
