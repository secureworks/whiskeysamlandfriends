# Copyright 2021 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid
import base64
import logging
import requests
from xml.etree import ElementTree
from ticketsplease.modules.azure.defs import NAMESPACES


class TOKEN:
    def _create_envelope(
        self,
        domain: str,
        requestId: str,
    ) -> str:
        """Create an envelope to be sent to Azure to request a
        desktop SSO token.

        Arguments:
            domain: public Azure tenant domain
            requestId: arbitrary ID for request

        Returns:
            Azure request envelope
        """
        guid = str(uuid.uuid4())
        envelope = f"""
    <?xml version='1.0' encoding='UTF-8'?>
        <s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:wsse='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd' xmlns:saml='urn:oasis:names:tc:SAML:1.0:assertion' xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy' xmlns:wsu='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd' xmlns:wsa='http://www.w3.org/2005/08/addressing' xmlns:wssc='http://schemas.xmlsoap.org/ws/2005/02/sc' xmlns:wst='http://schemas.xmlsoap.org/ws/2005/02/trust'>
            <s:Header>
                <wsa:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
                <wsa:To s:mustUnderstand='1'>https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/windowstransport?client-request-id={requestId}</wsa:To>
                <wsa:MessageID>urn:uuid:{guid}</wsa:MessageID>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken Id='RST0'>
                    <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
                        <wsp:AppliesTo>
                            <wsa:EndpointReference>
                                   <wsa:Address>urn:federation:MicrosoftOnline</wsa:Address>
                            </wsa:EndpointReference>
                        </wsp:AppliesTo>
                        <wst:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</wst:KeyType>
                    </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>"""
        return envelope.rstrip()

    def _send_envelope(
        self,
        domain: str,
        requestId: str,
        ticket: str,
        envelope: str,
    ) -> requests.Response:
        """Send the request envelope to Azure.

        Arguments:
            domain: domain name
            requestId: arbitrary ID for request
            ticket: base64 encoded kerberos ticket
            envelope: envelope to send

        Returns:
            Azure Server Response (xml)
        """
        url = f"https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/windowstransport?client-request-id={requestId}"
        headers = {
            "SOAPAction": "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
            "Authorization": f"Negotiate {ticket}",
        }

        try:
            response = requests.post(
                url,
                data=envelope,
                headers=headers,
            )
            return response
        except Exception as e:
            logging.error(e)
            raise TypeError("failed to send request envelope to Azure") from e

    def _parse_envelope(self, envelope: requests.Response) -> str:
        """Parse the response envelope from Azure.

        Arguments:
            envelope: requests.response xml

        Returns:
            dsso_token: required token to obtain JWT
        """
        try:
            tree = ElementTree.fromstring(envelope.text)
            dsso_token = tree.find(".//saml:Assertion", NAMESPACES["saml"])[0].text

            logging.debug(f"DesktopSSO Token:\n{dsso_token}")

            return dsso_token
        except Exception as e:
            logging.error(e)
            raise TypeError("server responded with malformed response") from e

    def _get_access_token(
        self,
        client_id: str,
        resource: str,
        dsso_token: str,
    ) -> requests.Response:
        """Using dsso_token, make request to Azure to obtain a JWT access token.

        Arguments:
            client_id: client_id of the target resource
            resource: API endpoint to request access token for
            dsso_token: desktop SSO token

        Returns:
            access token JWT
        """
        saml_assertion = f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"><DesktopSsoToken>{dsso_token}</DesktopSsoToken></saml:Assertion>'
        b64_assertion = base64.b64encode(saml_assertion.encode())

        url = "https://login.microsoftonline.com/common/oauth2/token"
        body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            "assertion": b64_assertion.decode(),
            "client_id": client_id,
            "resource": resource,
            "tbidv2": "",  # Optional, see https://tools.ietf.org/html/draft-ietf-tokbind-protocol-19
            "scope": "openid",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",  # Originally: "ms-appx-web://Microsoft.AAD.BrokerPlugin/$clientId"
            "win_ver": "10.0.17763.529",
            "windows_api_version": "2.0",
            "msafed": "0",
        }

        try:
            response = requests.post(url, data=body)
            return response
        except Exception as e:
            logging.error(e)
            raise TypeError("failed to request an access token") from e

    def _get_access_token_saml(
        self,
        client_id: str,
        resource: str,
        saml_token: str,
    ):
        """Using a golden SAML token, make request to Azure to obtain a JWT access token.

        Arguments:
            client_id: client_id of the target resource
            resource: API endpoint to request access token for
            saml_token: golden saml token assertion

        Returns:
            access token JWT
        """
        url = "https://login.microsoftonline.com/common/oauth2/token"
        headers = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; Tablet PC 2.0; Microsoft Outlook 16.0.4266)",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        body = {
            "resource": resource,
            "client_id": client_id,
            "grant_type": "urn:ietf:params:oauth:grant-type:saml1_1-bearer",
            "assertion": saml_token,
            "scope": "openid",
        }

        try:
            response = requests.post(url, headers=headers, data=body)
            return response
        except Exception as e:
            logging.error(e)
            raise TypeError("failed to request an access token") from e

    @classmethod
    def request_access_token(
        cls,
        domain: str,
        resource: str,
        client_id: str,
        krb_ticket: str = None,
        saml_token: str = None,
    ) -> str:
        """Create an envelope and send it to Azure and receive a JWT Access Token

        Arguments:
            domain: public Azure tenant domain
            resource: API endpoint to request access token for
            client_id: client_id of the target resource

        Returns:
            JWT Access Token
        """
        # Validate arguments
        if not krb_ticket and not saml_token:
            raise ValueError(
                "kerberos ticket or saml token required for authentication"
            )

        # Handle Kerberos ticket request
        if krb_ticket:
            requestId = uuid.uuid4()

            logging.info(f"[ * ] Building and sending RST envelope to Azure AD SSO")
            envelope = cls._create_envelope(cls, domain, requestId)
            envelope_response = cls._send_envelope(
                cls,
                domain=domain,
                requestId=requestId,
                ticket=krb_ticket,
                envelope=envelope,
            )

            logging.debug(f"RST Envelope:\n{envelope}")
            logging.debug(f"Azure Response Status: {envelope_response.status_code}")
            logging.debug(f"Azure Response:\n{envelope_response.content}")

            logging.info(f"[ * ] Parsing the RST response envelope from Azure")
            token = cls._parse_envelope(cls, envelope_response)

            if not token:
                raise TypeError("Azure did not return the DSSO Token")

            req_function = cls._get_access_token

        # Handle Golden SAML token
        else:
            token = saml_token
            req_function = cls._get_access_token_saml

        logging.info(f"[ * ] Requesting Access Token from Azure for: {resource}")
        access_token_response = req_function(
            cls,
            client_id,
            resource,
            token,
        )
        access_token = access_token_response.json()

        logging.debug(f"Access Token Status: {access_token_response.status_code}")
        logging.debug(f"Access Token Response:\n{access_token_response.content}")

        if access_token:
            return access_token
        else:
            raise TypeError("Azure did not return an Access Token")
