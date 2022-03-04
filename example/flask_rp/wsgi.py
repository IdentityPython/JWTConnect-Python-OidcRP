#!/usr/bin/env python3

import os
import sys

from oidcmsg.configure import create_from_config_file

from oidcrp.configure import Configuration
from oidcrp.configure import RPConfiguration
from oidcrp.util import create_context

try:
    from . import application
except ImportError:
    import application

dir_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == "__main__":
    conf = sys.argv[1]
    name = 'oidc_rp'
    template_dir = os.path.join(dir_path, 'templates')

    _config = create_from_config_file(Configuration,
                                      entity_conf=[{"class": RPConfiguration, "attr": "rp"}],
                                      filename=conf)

    app = application.oidc_provider_init_app(_config.rp, name, template_folder=template_dir)
    _web_conf = _config.web_conf
    context = create_context(dir_path, _web_conf)

    debug = _web_conf.get('debug', True)
    app.run(host=_web_conf["domain"], port=_web_conf["port"],
            debug=_web_conf.get("debug", False), ssl_context=context)
