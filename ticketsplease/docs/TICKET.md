# ticket Module

This module will generate a Kerberos ticket. It will either build a default KRB_TGT or if the `--ap-req` flag is provided, a ticket with the following hierarchy:

```
  SPNEGO_NegTokenInit
,---------------------,
|       AP_REQ        |
|  ,---------------,  |
|  |    KRB_TGT    |  |
|  '---------------'  |
|                     |
'---------------------'
```

## How it Works

| Step | Process |
| ---  | ---     |
| 1a   | If the required data (both the target user SID and hash) are not provided, a DCSync operation is performed to retrieve it. |
| 1b   | If only the the target user hash has been provided, an LDAP query is made to retrieve the target user SID. |
| 2    | Using the SID and hash of the target user, a KRB_TGT object is created via Impacket's ticketer<span>.py. |
| 3    | The KRB_TGT object is then wrapped in a custom AP_REQ message. |
| 4    | The AP_REQ message is then wrapped in a final SPNEGO_NegTokenInit message. |

> If the SID and hash required for use are for differing accounts, retrieve the required data via the `dcsync` module and pass them directly to this module.

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease ticket [-h] [--domain DOMAIN] [--spn-host SPN_HOST]
                            [--target-user TARGET_USER]
                            [--target-user-password TARGET_USER_PASSWORD]
                            [--target-user-hash TARGET_USER_HASH]
                            [--target-user-sid TARGET_USER_SID] [--ap-req] [--debug]
                            [--domain-username DOMAIN_USERNAME] [--domain-password DOMAIN_PASSWORD]
                            [--domain-hash DOMAIN_HASH] [--dc-ip DC_IP]

Generate a Kerberos ticket

optional arguments:
  -h, --help            show this help message and exit

  --domain DOMAIN       Target domain the Kerberos ticket is generated for (i.e. company.com).

  --spn-host SPN_HOST   SPN host - if differing from domain (otherwise, defaults to value of
                        --domain).

  --target-user TARGET_USER
                        Username of the account to generate the Kerberos ticket for (required
                        if no SID or password is provided).

  --target-user-password TARGET_USER_PASSWORD
                        Password of the user to generate a ticket for (if not provided,
                        retrieved via DCSync using --target-user).

  --target-user-hash TARGET_USER_HASH
                        Password hash of the user to generate a ticket for (supersedes
                        --user-password).

  --target-user-sid TARGET_USER_SID
                        SID of the user to generate a ticket for (if not provided, retrieved
                        via LDAP using --target-user).

  --ap-req              Wrap the Kerberos ticket in an AP_REQ message.

  --debug               Enable debugging.

dcsync/ldap arguments:
  --domain-username DOMAIN_USERNAME
                        Username to perform DCSync/LDAP operations with.

  --domain-password DOMAIN_PASSWORD
                        Password of the account to perform DCSync/LDAP operations with.

  --domain-hash DOMAIN_HASH
                        Password hash of the account to perform DCSync/LDAP operations
                        with (supersedes --domain-password).

  --dc-ip DC_IP         IP address of the target Domain Controller.

example usage:

    ticketsplease ticket --domain company.com --target-user-sid '...' --target-user-hash '...'
    ticketsplease ticket --domain company.com --target-user user --domain-username admin \
                         --domain-password password --dc-ip 10.10.10.10
```

## Arguments - Use Cases

The `--target-user`'s SID and password hash are used to identify and encrypt the ticket respectively.

1. When you do not have the SID and password/password hash of the target user, a DCSync operation is run to retrieve the data based on the `--target-user` value.
```
--domain <> --target-user <> --domain-username <> --domain-password <> --dc-ip <>
```

2. If you have the password/password hash of the target user, an LDAP query is made to retrieve the user's SID based on the `--target-user` value.
```
--domain <> --target-user <> --domain-username <> --domain-password <> --dc-ip <> --target-user-hash <>
```

3. If you have both the SID and password/password hash of the target user, LDAP and DCSync operations are skipped and the associated arguments are no longer required.
```
# SID and password are known
--domain <> --target-user-sid <> --target-user-password <>

# SID and password hash are known
--domain <> --target-user-sid <> --target-user-hash <>
```

## Importing the Module

```python
from ticketsplease.modules.ticket import create_ticket

# This method will piece together all of the module
# handlers to generate a ticket
ticket = create_ticket(
    domain,
    host,
    user,
    user_sid,
    user_password,
    user_hash,
    domain_username,
    domain_password,
    domain_hash,
    dc_ip,
    ap_req,
)
```

## Module Handlers

### krb_tgt.py

This will generate a KRB_TGT based on the provided arguments. It is a wrapper around Impacket's ticketer<span>.py example script and will invoke the TICKETER class.

### impacketx/ticketer.py

This is a slightly modified version of [Impacket's ticketer.py script](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py). To see modifications made, view the [custom ticketer script](../ticketsplease/modules/ticket/impacketx/ticketer.py) and see line comments starting with `NOTE:`.

### ap_req.py

This will take in a Kerberos ticket and wrap it in a AP_REQ message. This leverages the Impacket library to build the AP_REQ data structure manually and then wrapping it in SPNEGO_NegTokenInit message.
