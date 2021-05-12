from oidcrp.util import importer


def do_add_ons(add_ons, services):
    for key, spec in add_ons.items():
        _func = importer(spec['function'])
        _func(services, **spec['kwargs'])
