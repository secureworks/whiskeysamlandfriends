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

# XML Namespaces
NAMESPACES = {
    "wsa": {
        "wsa": "http://www.w3.org/2005/08/addressing",
    },
    "wsse": {
        "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    },
    "wsu": {
        "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    },
    "wsp": {
        "wsp": "http://schemas.xmlsoap.org/ws/2004/09/policy",
    },
    "wst": {
        "wst": "http://schemas.xmlsoap.org/ws/2005/02/trust",
    },
    "S": {
        "S": "http://www.w3.org/2003/05/soap-envelope",
    },
    "saml": {
        "saml": "urn:oasis:names:tc:SAML:1.0:assertion",
    },
    "a": {
        "a": "http://schemas.xmlsoap.org/ws/2009/09/identity/claims",
    },
    "tn": {
        "tn": "http://www.w3.org/2001/XMLSchema",
    },
    "b": {
        "b": "http://www.w3.org/2001/XMLSchema-instance",
    },
    "ds": {
        "ds": "http://www.w3.org/2000/09/xmldsig#",
    },
}

# Target endpoits to request an access token for
ENDPOINTS = {
    "ms_graph": {
        "resource": "https://graph.microsoft.com",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
    },
    "pta": {
        "resource": "https://proxy.cloudwebappproxy.net/registerapp",
        "client_id": "cb1056e2-e479-49de-ae31-7812af012ed8",
    },
    "office_apps": {
        "resource": "https://officeapps.live.com",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",  # "ab9b8c07-8f02-4f72-87fa-80105867a763"
    },
    "sara": {
        "resource": "https://api.diagnostics.office.com",
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    },
    "azure_core_mgmt": {
        "resource": "https://management.core.windows.net/",
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    },
    "aad_iam_api": {
        "resource": "https://graph.windows.net",
        "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    },
    "azure_graph": {
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
    },
    # TODO: The following need to be tested against a tenant that has OneDrive
    #       and SPO set up.
    #   Is -admin always valid for SPO or is this something we should handle
    #   via conditionals
    "onedrive": {
        "resource": "https://{tenant}-my.sharepoint.com/",
        "client_id": "ab9b8c07-8f02-4f72-87fa-80105867a763",
    },
    "spo": {
        "resource": "https://{tenant}-admin.sharepoint.com/",
        "client_id": "9bc3ab49-b65d-410a-85ad-de819febfddc",
    },
    # TODO: The below two error out with the following error message:
    #   The reply URL specified in the request does not match the reply URLs configured for the application
    # "exops": {
    #     "resource": "https://outlook.office365.com",
    #     "client_id": "a0c73c16-a7e3-4564-9a95-2bdf47383716",
    # },
    # "cloud_shell": {
    #     "resource": "https://management.core.windows.net/",
    #     "client_id": "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa",
    # },
}
