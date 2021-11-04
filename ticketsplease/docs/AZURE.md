# azure Module

This module will request Access Tokens from a specified Azure API endpoint using either a Kerberos ticket or a Golden SAML token.

> This module requires one of the following: a Kerberos ticket and the key that was generated via the `ticket` module or a Golden SAML token that was generated via the `saml` module. See the [Kerberos Ticket](#kerberos-ticket-1) section for important details on generating the Kerberos ticket.

## How it Works

### Kerberos Ticket

| Step | Process |
| ---  | ---     |
| 1    | An RST (RequestSecurityToken) envelope with the provided Kerberos ticket as an auth bearer is sent to Microsoft. |
| 2    | The RST response is parsed for the security token. |
| 3    | The security token is sent in a request to the Azure API endpoint requesting an access token. |

### Golden SAML

| Step | Process |
| ---  | ---     |
| 1    | The provided Golden SAML token is sent in a request to the Azure API endpoint requesting an access token. |

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease azure [-h] [--domain DOMAIN] [--api API] [--api-tenant API_TENANT] [--debug]
                           [--krb-ticket KRB_TICKET] [--saml-token SAML_TOKEN]

Request an Azure API Access Token

optional arguments:
  -h, --help            show this help message and exit

  --domain DOMAIN       Public Azure tenant domain (i.e. company.com)

  --api API             Target API endpoint to generate a token for. Choices: ['ms_graph',
                        'pta', 'office_apps', 'sara', 'azure_core_mgmt', 'aad_iam_api',
                        'azure_graph', 'onedrive', 'spo']

  --api-tenant API_TENANT
                        Tenant name to use in API endpoint calls (i.e. Sharepoint and OneDrive).

  --debug               Enable debugging.

  --krb-ticket KRB_TICKET
                        Base64 encoded Kerberos ticket.

  --saml-token SAML_TOKEN
                        Base64 encoded Golden SAML token Assertion.

example usage:

    ticketsplease azure --domain company.com --api azure_graph --krb-ticket '...'
    ticketsplease azure --domain company.com --api azure_graph --saml-token '...'

note:
    If a Kerberos ticket is provided, the SID to use is for the target user to impersonate,
    but the hash for encryption is for the Azure AD DesktopSSOAccount - the default account
    name is: 'AZUREADSSOACC$'.
```

## Arguments - Use Cases

### Kerberos Ticket

When building a Kerberos ticket to be used for requesting an access token, the SID should reflect the target user for impersonation, but the password hash should reflect the Azure AD DesktopSSOAccount (default name is 'AZUREADSSOACC$').

```
--domain <> --api <> --krb-ticket <>
```

### Golden SAML

```
--domain <> --api <> --saml-token <>
```

## Importing the Module

```python
from ticketsplease.modules.azure import request_access_token

# This method will piece together all of the module handlers
# to request an Access Token from the specified Azure API
# endpoint
(access_token, refresh_token) = request_access_token(
    domain,
    api,
    api_tenant,
    krb_ticket,
    saml_token,
)
```

## Module Handlers

### token.py

This will take in the Kerberos ticket or Golden SAML token and request an access token from the specified Azure API endpoint.

### defs.py

This is storage for the XML namespaces and Azure API endpoints.