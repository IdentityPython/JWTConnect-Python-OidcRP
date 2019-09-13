#!/usr/bin/env python3

import logging
import os
import sys

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
RP_LOGFILE_NAME = os.environ.get('RP_LOGFILE_NAME', 'flrp.log')

hdlr = logging.FileHandler(RP_LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s  [%(name)s.%(funcName)s:%(lineno)s]")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    conf = sys.argv[1]
    name = 'oidc_rp'
    template_dir = os.path.join(dir_path, 'templates')
    app = application.oidc_provider_init_app(conf, name,
                                             template_folder=template_dir)

    app.run(host='127.0.0.1', port=app.config.get('PORT'),
            debug=True,
            ssl_context=('{}/certs/cert.pem'.format(dir_path),
                         '{}/certs/key.pem'.format(dir_path))
            )
