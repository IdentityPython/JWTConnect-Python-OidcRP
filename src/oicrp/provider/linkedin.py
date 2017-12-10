from oiccli import oic as oicc
from oiccli.oauth2 import service

from oicmsg import oauth2
from oicmsg import oic as oicm
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
    msg_type = Message
    response_cls =  UserSchema
    error_msg = oicm.UserInfoErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'
    default_authn_method = 'bearer_header'
    http_method = 'GET'
