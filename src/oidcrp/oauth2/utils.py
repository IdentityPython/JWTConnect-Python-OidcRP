from oidcmsg.exception import MissingParameter


def get_state_parameter(request_args, kwargs):
    """Find a state value from a set of possible places."""
    try:
        _state = kwargs['state']
    except KeyError:
        try:
            _state = request_args['state']
        except KeyError:
            raise MissingParameter('state')

    return _state


def pick_redirect_uris(request_args=None, service=None, **kwargs):
    """Pick one redirect_uri base on response_mode out of a list of such."""
    _context = service.client_get("service_context")

    if 'redirect_uri' in request_args:
        return request_args, {}

    _callback = _context.callback
    if _callback:
        try:
            _response_type = request_args['response_type']
        except KeyError:
            _response_type = _context.behaviour['response_types'][0]
            request_args['response_type'] = _response_type

        try:
            _response_mode = request_args['response_mode']
        except KeyError:
            _response_mode = ''

        if _response_mode == 'form_post':
            request_args['redirect_uri'] = _callback['form_post']
        elif _response_type == 'code':
            request_args['redirect_uri'] = _callback['code']
        else:
            request_args['redirect_uri'] = _callback['implicit']
    else:
        request_args['redirect_uri'] = _context.redirect_uris[0]

    return request_args, {}


def set_state_parameter(request_args=None, **kwargs):
    """Assigned a state value."""
    request_args['state'] = get_state_parameter(request_args, kwargs)
    return request_args, {'state': request_args['state']}
