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


def ldap_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `ldap` module"""
    example_usage = """example usage:

    ticketsplease ldap --username admin --password password --host 10.10.10.10
    ticketsplease ldap --target-user user --username admin --password password --host 10.10.10.10
    """

    ldap_parser = subparsers.add_parser(
        "ldap",
        description="Retrieve the DKM or the UPN/GUID/SID of a given user",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ldap_parser.add_argument(
        "--domain",
        type=str,
        help="Target domain the host to query is in (i.e. company.com).",
        required=True,
    )
    ldap_parser.add_argument(
        "--host",
        type=str,
        help="IP address of the target system to query via LDAP.",
        required=True,
    )
    ldap_parser.add_argument(
        "--username",
        type=str,
        help="Username to perform LDAP queries with.",
        required=True,
    )
    ldap_parser.add_argument(
        "--password",
        type=str,
        help="Password of the account to perform LDAP queries with.",
        required=True,
    )
    ldap_parser.add_argument(
        "--target-user",
        type=str,
        help="Target user to retrieve the UPN, GUID, and SID for (if not provided, DKM is retrieved).",
    )

    return ldap_parser
