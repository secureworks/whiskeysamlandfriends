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


def saml_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `saml` module"""
    example_usage = """example usage:

    ticketsplease saml --adfs-config '...' --target-user-guid '...' --dkm-key '...' --assertion
    ticketsplease saml --adfs-config-file config.bin --domain company.com --target-user tUser --domain-username user --domain-password password --dc-ip 10.10.10.10
    """

    saml_parser = subparsers.add_parser(
        "saml",
        description="Generate a Golden SAML token",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    saml_parser.add_argument(
        "--adfs-config",
        type=str,
        help="ADFS configuration settings.",
    )
    saml_parser.add_argument(
        "--adfs-config-file",
        type=str,
        help="File containing the ADFS configuration settings.",
    )
    saml_parser.add_argument(
        "--domain",
        type=str,
        help="Target domain the Golden SAML token is generated for (i.e. company.com).",
    )
    saml_parser.add_argument(
        "--target-user",
        type=str,
        help="Username of the account to generate the Golden SAML token for.",
    )
    saml_parser.add_argument(
        "--target-user-upn",
        type=str,
        help="UPN of the account to generate the Golden SAML token for (if not provided, retrieved via LDAP).",
    )
    saml_parser.add_argument(
        "--target-user-guid",
        type=str,
        help="GUID of the account to generate the Golden SAML token for (if not provided, retrieved via LDAP).",
    )
    saml_parser.add_argument(
        "--dkm-key",
        type=str,
        help="DKM Key (if not provided, retrieved via LDAP).",
    )
    saml_parser.add_argument(
        "--assertion",
        action="store_true",
        help="Extract the SAML Assertion from the token.",
    )
    # LDAP/WMIC options
    domain_saml_options = saml_parser.add_argument_group("ldap/wmic arguments")
    domain_saml_options.add_argument(
        "--domain-username",
        type=str,
        help="Username to perform LDAP/WMIC operations with.",
    )
    domain_saml_options.add_argument(
        "--domain-password",
        type=str,
        help="Password of the account to perform LDAP/WMIC operations with.",
    )
    domain_saml_options.add_argument(
        "--dc-ip",
        type=str,
        help="IP address of the target Domain Controller.",
    )

    return saml_parser
