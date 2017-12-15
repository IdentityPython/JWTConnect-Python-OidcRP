from oic.oauth2 import ErrorResponse
from oiccli import oic as oicc

from oicmsg.message import Message


class UserInfo(oicc.service.UserInfo):
    msg_type = Message
    response_cls = Message
    error_msg = ErrorResponse
    endpoint_name = 'userinfo_endpoint'
    synchronous = True
    request = 'userinfo'
    default_authn_method = ''
    http_method = 'GET'
