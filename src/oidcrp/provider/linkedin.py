from oidcmsg import oauth2
from oidcmsg.message import Message
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_STRING

from oidcservice.oauth2 import access_token
from oidcservice.oidc import userinfo


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


class AccessToken(access_token.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse


class UserInfo(userinfo.UserInfo):
    response_cls = UserSchema
