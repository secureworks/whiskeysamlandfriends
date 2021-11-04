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

import argparse


def ticket_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `ticket` module"""
    example_usage = """example usage:

    ticketsplease ticket --domain company.com --target-user-sid '...' --target-user-hash '...'
    ticketsplease ticket --domain company.com --target-user user --domain-username admin --domain-password password --dc-ip 10.10.10.10
    """

    ticket_parser = subparsers.add_parser(
        "ticket",
        description="Generate a Kerberos ticket",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ticket_parser.add_argument(
        "--domain",
        type=str,
        help="Target domain the Kerberos ticket is generated for (i.e. company.com).",
    )
    ticket_parser.add_argument(
        "--spn-host",
        type=str,
        help="SPN host - if differing from domain (otherwise, defaults to value of --domain).",
    )
    ticket_parser.add_argument(
        "--target-user",
        type=str,
        help="Username of the account to generate the Kerberos ticket for (required if no SID or password is provided).",
    )
    ticket_parser.add_argument(
        "--target-user-password",
        type=str,
        help="Password of the user to generate a ticket for (if not provided, retrieved via DCSync using --target-user).",
    )
    ticket_parser.add_argument(
        "--target-user-hash",
        type=str,
        help="Password hash of the user to generate a ticket for (supersedes --user-password).",
    )
    ticket_parser.add_argument(
        "--target-user-sid",
        type=str,
        help="SID of the user to generate a ticket for (if not provided, retrieved via LDAP using --target-user).",
    )
    ticket_parser.add_argument(
        "--ap-req",
        action="store_true",
        help="Wrap the Kerberos ticket in an AP_REQ message.",
    )
    # DCSync/LDAP options
    domain_tickets_options = ticket_parser.add_argument_group("dcsync/ldap arguments")
    domain_tickets_options.add_argument(
        "--domain-username",
        type=str,
        help="Username to perform DCSync/LDAP operations with.",
    )
    domain_tickets_options.add_argument(
        "--domain-password",
        type=str,
        help="Password of the account to perform DCSync/LDAP operations with.",
    )
    domain_tickets_options.add_argument(
        "--domain-hash",
        type=str,
        help="Password hash of the account to perform DCSync/LDAP operations with (supersedes --domain-password).",
    )
    domain_tickets_options.add_argument(
        "--dc-ip",
        type=str,
        help="IP address of the target Domain Controller.",
    )

    return ticket_parser
