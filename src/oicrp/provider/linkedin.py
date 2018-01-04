from oiccli import oic as oicc
from oiccli.oauth2 import service

from oicmsg import oauth2
from oicmsg.message import Message
from oicmsg.message import SINGLE_OPTIONAL_JSON
from oicmsg.message import SINGLE_OPTIONAL_STRING
from oicmsg.message import SINGLE_REQUIRED_INT
from oicmsg.message import SINGLE_REQUIRED_STRING


class AccessTokenResponse(Message):
    """
    Access token response
    """
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_REQUIRED_INT
    }


class UserSchema(Message):
    c_param = {
        "firstName": SINGLE_OPTIONAL_STRING,
        "headline": SINGLE_OPTIONAL_STRING,
        "id": SINGLE_REQUIRED_STRING,
        "lastName": SINGLE_OPTIONAL_STRING,
        "siteStandardProfileRequest": SINGLE_OPTIONAL_JSON
    }


class AccessToken(service.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse


class UserInfo(oicc.service.UserInfo):
    response_cls = UserSchema
    http_method = 'GET'
