#!/usr/bin/env python3

import logging
import os
import sys

from oidcrp.util import create_context

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
RP_LOGFILE_NAME = os.environ.get('RP_LOGFILE_NAME', 'flrp.log')

hdlr = logging.FileHandler(RP_LOGFILE_NAME)
log_format = ("%(asctime)s %(name)s:%(levelname)s "
              "%(message)s  [%(name)s.%(funcName)s:%(lineno)s]")
base_formatter = logging.Formatter(log_format)

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

stdout = logging.StreamHandler()
stdout.setFormatter(base_formatter)
logger.addHandler(stdout)

dir_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    conf = sys.argv[1]
    name = 'oidc_rp'
    template_dir = os.path.join(dir_path, 'templates')
    app = application.oidc_provider_init_app(conf, name,
                                             template_folder=template_dir)
    _web_conf = app.rp_config.web_conf
    context = create_context(dir_path, _web_conf)

    debug = _web_conf.get('debug', True)
    app.run(host=app.rp_config.domain, port=app.rp_config.port,
            debug=_web_conf.get("debug", False), ssl_context=context)
