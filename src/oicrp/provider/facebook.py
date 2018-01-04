from oiccli import oic as oicc
from oiccli.oauth2 import service

from oicmsg import oauth2
from oicmsg.message import Message


class AccessToken(service.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    error_msg = oauth2.TokenErrorResponse
    default_authn_method = ''


class UserInfo(oicc.service.UserInfo):
    response_cls = Message
    http_method = 'GET'
