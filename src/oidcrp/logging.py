"""Common logging functions"""

import os
import logging
from logging.config import dictConfig

import yaml


LOGGING_CONF = 'logging.yaml'

LOGGING_DEFAULT = {
    'version': 1,
    'formatters': {
        'default': {
            'format': '%(asctime)s %(name)s %(levelname)s %(message)s'
        }
    },
    'handlers': {
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default'
        }
    },
    'root': {
        'handlers': ['default'],
        'level': 'INFO'
    }
}


def configure_logging(debug: bool = False, config: dict = None,
                      filename: str = LOGGING_CONF) -> logging.Logger:
    """Configure logging"""

    if config is not None:
        config_dict = config
        config_source = 'dictionary'
    elif filename is not None and os.path.exists(filename):
        with open(filename, "rt") as file:
            config_dict = yaml.load(file)
        config_source = 'file'
    else:
        config_dict = LOGGING_DEFAULT
        config_source = 'default'

    if debug:
        config_dict['root']['level'] = 'DEBUG'

    dictConfig(config_dict)
    logging.debug("Configured logging using %s", config_source)
    return logging.getLogger()
