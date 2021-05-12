import logging

from cryptojwt import JWT
from oidcmsg.message import Message
from oidcmsg.oauth2 import JWTSecuredAuthorizationRequest
import requests

logger = logging.getLogger(__name__)


def push_authorization(request_args, service, **kwargs):
    """
    :param request_args: All the request arguments as a AuthorizationRequest instance
    :param service: The service to which this post construct method is applied.
    :param kwargs: Extra keyword arguments.
    """

    _context = service.client_get("service_context")
    method_args = _context.add_on["pushed_authorization"]

    # construct the message body
    if method_args["body_format"] == "urlencoded":
        _body = request_args.to_urlencoded()
    else:
        _jwt = JWT(key_jar=_context.keyjar, iss=_context.base_url)
        _jws = _jwt.pack(request_args.to_dict())

        _msg = Message(request=_jws)
        if method_args["merge_rule"] == "lax":
            for param in request_args.required_parameters():
                _msg[param] = request_args.get(param)

        _body = _msg.to_urlencoded()

    # Send it to the Pushed Authorization Request Endpoint
    resp = method_args["http_client"].get(
        _context.provider_info["pushed_authorization_request_endpoint"], data=_body
    )

    if resp.status_code == 200:
        _resp = Message().from_json(resp.text)
        _req = JWTSecuredAuthorizationRequest(request_uri=_resp["request_uri"])
        if method_args["merge_rule"] == "lax":
            for param in request_args.required_parameters():
                _req[param] = request_args.get(param)
        request_args = _req

    return request_args


def add_support(services, body_format="jws", signing_algorithm="RS256",
                http_client=None, merge_rule="strict"):
    """
    Add the necessary pieces to make pushed authorization happen.

    :param merge_rule:
    :param http_client:
    :param signing_algorithm:
    :param services: A dictionary with all the services the client has access to.
    :param body_format: jws or urlencoded
    """

    if http_client is None:
        http_client = requests

    _service = services["authorization"]
    _service.client_get("service_context").add_on['pushed_authorization'] = {
        "body_format": body_format,
        "signing_algorithm": signing_algorithm,
        "http_client": http_client,
        "merge_rule": merge_rule
    }

    _service.post_construct.append(push_authorization)
