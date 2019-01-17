from oidcmsg import oauth2
from oidcmsg.message import Message
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.oauth2 import ResponseMessage
from oidcservice.oauth2 import access_token
from oidcservice.oidc import userinfo


class AccessTokenResponse(Message):
    """
    Access token response
    """
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING
    }


class AccessToken(access_token.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse
    response_body_type = 'urlencoded'


class UserInfo(userinfo.UserInfo):
    response_cls = Message
    error_msg = ResponseMessage
    default_authn_method = ''
    http_method = 'GET'
