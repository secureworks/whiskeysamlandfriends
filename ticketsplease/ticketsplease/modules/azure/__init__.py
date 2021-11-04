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

from ticketsplease.modules.azure.token import TOKEN
from ticketsplease.modules.azure.defs import ENDPOINTS


def request_access_token(
    domain: str = None,
    api: str = "azure_graph",
    api_tenant: str = None,
    krb_ticket: str = None,
    saml_token: str = None,
):
    """Request an Access Token for a given API endpoint using either
    Kerberos or SAML.

    Arguments:
        domain: target domain
        api: api endpoint to request access token for
        api_tenant: tenant name for API endpoints like SharePoint
        krb_ticket: kerberos ticket
        saml_token: golden saml token

    Returns:
        access and request token for the specified API endpoint

    Raises:
        ValueError: if kerberos ticket or saml token missing
    """
    # Validate arguments
    if not krb_ticket and not saml_token:
        raise ValueError(
            "kerberos ticket or golden saml token required for authentication"
        )

    # NOTE: The kerberos ticket requires the SID of the target user, but
    #       the password hash of the SSO user

    # Request the access token for a given resource
    api_endpoint = ENDPOINTS[api]
    access_token_json = TOKEN.request_access_token(
        domain=domain,
        resource=api_endpoint["resource"].format(tenant=api_tenant),
        client_id=api_endpoint["client_id"],
        krb_ticket=krb_ticket,
        saml_token=saml_token,
    )
    access_token = access_token_json["access_token"]
    refresh_token = access_token_json["refresh_token"]

    return (access_token, refresh_token)
