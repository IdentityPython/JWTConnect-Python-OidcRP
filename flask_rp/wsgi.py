import logging
import os

try:
    from . import application
except ImportError:
    import application

logger = logging.getLogger("")
LOGFILE_NAME = 'flrp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

dir_path = os.path.dirname(os.path.realpath(__file__))

template_dir = os.path.join(dir_path, 'templates')

name = 'oidc_rp'
app = application.oidc_provider_init_app('fc_conf.py', name, template_folder=template_dir)
logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=app.config.get('PORT'),
            debug=True,
            ssl_context=('{}/certs/cert.pem'.format(dir_path),
                         '{}/certs/key.pem'.format(dir_path))
            )
