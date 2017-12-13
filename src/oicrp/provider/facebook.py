from oiccli import oic as oicc
from oiccli.oauth2 import service

from oicmsg import oauth2
from oicmsg import oic as oicm
from oicmsg.message import Message


class AccessToken(service.AccessToken):
    msg_type = oauth2.AccessTokenRequest
    error_msg = oauth2.TokenErrorResponse
    default_authn_method = ''


class UserInfo(oicc.service.UserInfo):
    msg_type = Message
    response_cls = Message
    error_msg = oicm.UserInfoErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'
    default_authn_method = 'bearer_header'
    http_method = 'GET'
