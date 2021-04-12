import logging

from oidcmsg import oidc
from oidcmsg.message import Message
from oidcmsg.oauth2 import ResponseMessage

from oidcrp.service import Service

LOGGER = logging.getLogger(__name__)


class RegistrationRead(Service):
    msg_type = Message
    response_cls = oidc.RegistrationResponse
    error_msg = ResponseMessage
    synchronous = True
    service_name = 'registration_read'
    http_method = 'GET'
    default_authn_method = 'client_secret_basic'

    def get_endpoint(self):
        try:
            return self.client_get("service_context").registration_response["registration_client_uri"]
        except KeyError:
            return ''

    def get_authn_header(self, request, authn_method, **kwargs):
        """
        Construct an authorization specification to be sent in the
        HTTP header.

        :param request: The service request
        :param authn_method: Which authentication/authorization method to use
        :param kwargs: Extra keyword arguments
        :return: A set of keyword arguments to be sent in the HTTP header.
        """
        headers = {}

        if authn_method == "client_secret_basic":
            LOGGER.debug("Client authn method: %s", authn_method)
            headers["Authorization"] = "Bearer {}".format(
                self.client_get("service_context").registration_response[
                    "registration_access_token"]
            )

        return headers