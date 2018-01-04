from oiccli import oic as oicc
from oicmsg import oauth2
from oicmsg.oauth2 import ErrorResponse
from oiccli.oauth2 import service

from oicmsg.message import Message
from oicmsg.message import SINGLE_OPTIONAL_STRING
from oicmsg.message import SINGLE_REQUIRED_STRING


class AccessTokenResponse(Message):
    """
    Access token response
    """
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING
    }


class AccessToken(service.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse
    response_body_type = 'urlencoded'


class UserInfo(oicc.service.UserInfo):
    response_cls = Message
    error_msg = ErrorResponse
    default_authn_method = ''
    http_method = 'GET'
