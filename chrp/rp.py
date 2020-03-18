#!/usr/bin/env python3
import cherrypy
import importlib
import logging
import os
import sys

from cryptojwt.key_jar import init_key_jar

from oidcrp import RPHandler

logger = logging.getLogger("")
LOGFILE_NAME = 'farp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


SIGKEY_NAME = 'sigkey.jwks'


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest='tls', action='store_true')
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    folder = os.path.abspath(os.curdir)
    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    try:
        _port = config.PORT
    except AttributeError:
        if args.tls:
            _port = 443
        else:
            _port = 80

    cherrypy.config.update(
        {'environment': 'production',
         'log.error_file': 'error.log',
         'log.access_file': 'access.log',
         'tools.trailing_slash.on': False,
         'server.socket_host': '0.0.0.0',
         'log.screen': True,
         'tools.sessions.on': True,
         'tools.encode.on': True,
         'tools.encode.encoding': 'utf-8',
         'server.socket_port': _port
         })

    provider_config = {
        '/': {
            'root_path': 'localhost',
            'log.screen': True
        },
        '/static': {
            'tools.staticdir.dir': os.path.join(folder, 'static'),
            'tools.staticdir.debug': True,
            'tools.staticdir.on': True,
            'tools.staticdir.content_types': {
                'json': 'application/json',
                'jwks': 'application/json',
                'jose': 'application/jose'
            },
            'log.screen': True,
            'cors.expose_public.on': True
        }}

    cprp = importlib.import_module('cprp')

    _base_url = config.BASEURL

    _kj = init_key_jar(public_path=config.PUBLIC_JWKS_PATH,
                       private_path=config.PRIVATE_JWKS_PATH,
                       key_defs=config.KEYDEFS)

    if args.insecure:
        _kj.verify_ssl = False
        _verify_ssl = False
    else:
        _verify_ssl = True

    rph = RPHandler(_base_url, config.CLIENTS, services=config.SERVICES,
                    hash_seed="BabyHoldOn", keyjar=_kj, jwks_path=config.PUBLIC_JWKS_PATH,
                    verify_ssl=_verify_ssl)

    cherrypy.tree.mount(cprp.Consumer(rph, 'html'), '/', provider_config)

    # If HTTPS
    if args.tls:
        cherrypy.server.ssl_certificate = config.SERVER_CERT
        cherrypy.server.ssl_private_key = config.SERVER_KEY
        if config.CA_BUNDLE:
            cherrypy.server.ssl_certificate_chain = config.CA_BUNDLE

    cherrypy.engine.start()
    cherrypy.engine.block()
