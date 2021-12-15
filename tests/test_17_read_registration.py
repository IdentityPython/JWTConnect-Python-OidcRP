import json
import time

from cryptojwt.utils import as_bytes
from oidcmsg.oidc import RegistrationResponse
import pytest
import responses

from oidcrp.entity import Entity
import requests

ISS = "https://example.com"
RP_BASEURL = "https://example.com/rp"


class TestRegistrationRead(object):
    @pytest.fixture(autouse=True)
    def create_request(self):
        self._iss = ISS
        client_config = {
            "redirect_uris": ["https://example.com/cli/authz_cb"],
            "issuer": self._iss, "requests_dir": "requests",
            "base_url": "https://example.com/cli/",
            "client_preferences": {
                "application_type": "web",
                "response_types": ["code"],
                "contacts": ["ops@example.org"],
                "jwks_uri": "https://example.com/rp/static/jwks.json",
                "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)],
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": ["authorization_code"]
            }
        }
        services = {
            'registration': {
                'class': 'oidcrp.oidc.registration.Registration'
            },
            'read_registration': {
                'class': 'oidcrp.oidc.read_registration.RegistrationRead'
            }
        }

        self.entity = Entity(config=client_config, services=services)

        self.reg_service = self.entity.client_get("service", 'registration')
        self.read_service = self.entity.client_get("service", 'registration_read')

    def test_construct(self):
        self.reg_service.endpoint = "{}/registration".format(ISS)

        _param = self.reg_service.get_request_parameters()

        now = int(time.time())

        _client_registration_response = json.dumps({
            "client_id": "zls2qhN1jO6A",
            "client_secret": "c8434f28cf9375d9a7",
            "registration_access_token": "NdGrGR7LCuzNtixvBFnDphGXv7wRcONn",
            "registration_client_uri": "{}/registration_api?client_id=zls2qhN1jO6A".format(ISS),
            "client_secret_expires_at": now + 3600,
            "client_id_issued_at": now,
            "application_type": "web",
            "response_types": ["code"],
            "contacts": ["ops@example.com"],
            "redirect_uris": ["{}/authz_cb".format(RP_BASEURL)],
            "token_endpoint_auth_method": "client_secret_basic",
            "grant_types": ["authorization_code"]
        })

        with responses.RequestsMock() as rsps:
            rsps.add(_param["method"], _param["url"], body=_client_registration_response,
                     status=200)
            _resp = requests.request(
                _param["method"], _param["url"],
                data=as_bytes(_param["body"]),
                headers=_param["headers"],
                verify=False
            )

        resp = self.reg_service.parse_response(_resp.text)
        self.reg_service.update_service_context(resp)

        assert resp

        _read_param = self.read_service.get_request_parameters()
        with responses.RequestsMock() as rsps:
            rsps.add(_param["method"], _param["url"], body=_client_registration_response,
                     adding_headers={"Content-Type": "application/json"}, status=200)
            _resp = requests.request(
                _param["method"],
                _param["url"],
                headers=_param["headers"],
                verify=False
            )

        read_resp = self.reg_service.parse_response(_resp.text)
        assert isinstance(read_resp, RegistrationResponse)
