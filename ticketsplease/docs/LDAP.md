# ldap Module

This module will perform an LDAP query to retrieve one of the following:
1. The DKM master key
2. The UPN, GUID, and SID of a specified user

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease ldap [-h] --host HOST --username USERNAME
                          --password PASSWORD [--target-user TARGET_USER] [--debug]

Retrieve the DKM or the UPN/GUID/SID of a given user

optional arguments:
  -h, --help            show this help message and exit

  --domain DOMAIN       Target domain the host to query is in (i.e. company.com).

  --host HOST           IP address of the target system to query via LDAP.

  --username USERNAME   Username to perform LDAP queries with.

  --password PASSWORD   Password of the account to perform LDAP queries with.

  --target-user TARGET_USER
                        Target user to retrieve the UPN, GUID, and SID for (if not
                        provided, DKM is retrieved).

  --debug               Enable debugging.

example usage:

    ticketsplease ldap --domain company.com --username admin --password password --host 10.10.10.10
    ticketsplease ldap --domain company.com --username admin --password password --host 10.10.10.10 \
                       --target-user user
```

## Importing the Module

```python
from ticketsplease.modules.ldap import LDAP

# Retrieve data for a given user
(upn, guid, sid) = LDAP.get_user(
    domain,
    host,
    user,
    password,
    target_user,
)

# Retrieve the DKM master key
dkm_key = LDAP.get_dkm(
    domain,
    host,
    user,
    password,
)
```