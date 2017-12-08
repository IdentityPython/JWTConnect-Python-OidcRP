from oiccli.oauth2 import requests
from oicmsg import oauth2
from oicmsg.message import Message
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


class AccessTokenRequest(requests.AccessTokenRequest):
    msg_type = oauth2.AccessTokenRequest
    response_cls = AccessTokenResponse
    error_msg = oauth2.TokenErrorResponse


