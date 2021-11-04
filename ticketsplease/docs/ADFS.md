# adfs Module

This module will remotely pull down the ADFS configuration settings. This is based on the AADInternals function: [Export-ADFSConfiguration](https://github.com/Gerenios/AADInternals/blob/master/ADFS.ps1#L133).

> This module requires a Kerberos ticket and the key that was generated via the `ticket` module.

## How it Works

| Step | Process |
| ---  | ---     |
| 1    | The provided kerberos ticket is sent to the ADFS server in an RST (RequestSecurityToken) envelope. |
| 2    | The RST response is parsed and sent back to the ADFS server as a SCT (SecurityContextToken) envelope. |
| 3    | Finally, the token is parsed from the SCT response and sent to the ADFS server requesting the configuration settings. |

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease adfs [-h] --adfs-host ADFS_HOST --krb-ticket KRB_TICKET
                          --krb-key KRB_KEY [--debug]

Remotely pull down the ADFS Configuration of a target ADFS server

optional arguments:
  -h, --help            show this help message and exit

  --adfs-host ADFS_HOST
                        Target ADFS server to retrieve the configuration from.

  --krb-ticket KRB_TICKET
                        Base64 encoded Kerberos ticket.

  --krb-key KRB_KEY     Base64 encoded key used when generating the provided
                        Kerberos ticket.

  --output              Write the ADFS config to 'config.bin'.

  --debug               Enable debugging.

example usage:

    ticketsplease adfs --adfs-host 10.10.10.10 --krb-key '...' --krb-ticket '...'
```

## Arguments - Use Cases

> This module requires the session key that was used to generate the Kerberos ticket which is outputted via the `ticket` module

```
--adfs-host <> --krb-key <> --krb-ticket <>
```

## Importing the Module

```python
from ticketsplease.modules.adfs import get_configuration

# This method will piece together all of the module handlers
# to retrieve the configuration (envelope request and parsing
# (RST and SCT), configuration request and parsing)
configuration = get_configuration(
    adfs_host,
    ticket,
    sessionKey,
    cipher,
)
```

## Module Handlers

### envelope/rst.py

This will take the provided AP_REQ message and create an RST (RequestSecurityToken) envelope to send to the ADFS server.

### envelope/sct.py

This will take the RST envelope response and create an SCT (SecurityContextToken) envelope to send to the ADFS server.

### envelope/adfs.py

This will take the SCT envleope response and create a final ADFS envelope to send to the ADFS server to retrieve and parse the configuration.

### envelope/utils.py

Helper functions based on AADInternals util handlers.

### configuration<span>.py

This will take in the ADFS configuration, parse it, and extract the `EncryptedPfx` and `Server Issuer` values.
