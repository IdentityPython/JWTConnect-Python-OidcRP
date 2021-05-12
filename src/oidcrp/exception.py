
__author__ = 'roland'


# The base exception class for oidc service specific exceptions
class OidcServiceError(Exception):
    def __init__(self, errmsg, content_type="", *args):
        Exception.__init__(self, errmsg, *args)
        self.content_type = content_type


class MissingRequiredAttribute(OidcServiceError):
    pass


class VerificationError(OidcServiceError):
    pass


class ResponseError(OidcServiceError):
    pass


class TimeFormatError(OidcServiceError):
    pass


class CapabilitiesMisMatch(OidcServiceError):
    pass


class MissingEndpoint(OidcServiceError):
    pass


class TokenError(OidcServiceError):
    pass


class GrantError(OidcServiceError):
    pass


class ParseError(OidcServiceError):
    pass


class OtherError(OidcServiceError):
    pass


class NoClientInfoReceivedError(OidcServiceError):
    pass


class InvalidRequest(OidcServiceError):
    pass


class NonFatalException(OidcServiceError):
    """
    :param resp: A response that the function/method would return on non-error
    :param msg: A message describing what error has occurred.
    """

    def __init__(self, resp, msg):
        self.resp = resp
        self.msg = msg


class Unsupported(OidcServiceError):
    pass


class UnsupportedResponseType(Unsupported):
    pass


class AccessDenied(OidcServiceError):
    pass


class ImproperlyConfigured(OidcServiceError):
    pass


class UnsupportedMethod(OidcServiceError):
    pass


class AuthzError(OidcServiceError):
    pass


class AuthnToOld(OidcServiceError):
    pass


class ParameterError(OidcServiceError):
    pass


class SubMismatch(OidcServiceError):
    pass


class ConfigurationError(OidcServiceError):
    pass


class WrongContentType(OidcServiceError):
    pass


class WebFingerError(OidcServiceError):
    pass


class HandlerError(Exception):
    pass


class HttpError(OidcServiceError):
    pass
