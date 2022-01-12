import os
import re

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from flask.app import Flask

from oidcrp.rp_handler import RPHandler

dir_path = os.path.dirname(os.path.realpath(__file__))


def init_oidc_rp_handler(app):
    _rp_conf = app.rp_config

    if _rp_conf.key_conf:
        _kj = init_key_jar(**_rp_conf.key_conf)
        _path = _rp_conf.key_conf['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = _rp_conf.httpc_params

    rph = RPHandler(_rp_conf.base_url, _rp_conf.clients, services=_rp_conf.services,
                    hash_seed=_rp_conf.hash_seed, keyjar=_kj, jwks_path=_path,
                    httpc_params=_rp_conf.httpc_params)

    return rph


def oidc_provider_init_app(config, name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)

    app.rp_config = config

    # Session key for the application session
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
