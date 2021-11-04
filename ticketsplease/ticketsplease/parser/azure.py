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
from ticketsplease.modules.azure.defs import ENDPOINTS


def azure_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `azure` module"""

    example_usage = """example usage:

    ticketsplease azure --domain company.com --api azure_graph --krb-ticket '...'
    ticketsplease azure --domain company.com --api azure_graph --saml-token '...'

    """
    example_usage += """note:
    If a Kerberos ticket is provided, the SID to use is for the target user to impersonate,
    but the hash for encryption is for the Azure AD DesktopSSOAccount - the default account
    name is: 'AZUREADSSOACC$'.
    """

    azure_parser = subparsers.add_parser(
        "azure",
        description="Request an Azure API Access Token",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    azure_parser.add_argument(
        "--domain",
        type=str,
        help="Public Azure tenant domain (i.e. company.com).",
    )
    azure_parser.add_argument(
        "--api",
        type=str,
        choices=ENDPOINTS.keys(),
        default="azure_graph",
        metavar="API",
        help=f"Target API endpoint to generate a token for. Choices: {list(ENDPOINTS.keys())}",
    )
    azure_parser.add_argument(
        "--api-tenant",
        type=str,
        help="Tenant name to use in API endpoint calls (i.e. Sharepoint and OneDrive).",
    )
    # Kerberos ticket option
    azure_parser.add_argument(
        "--krb-ticket",
        type=str,
        help="Base64 encoded Kerberos ticket.",
    )
    # Golden SAML option
    azure_parser.add_argument(
        "--saml-token",
        type=str,
        help="Base64 encoded Golden SAML token Assertion.",
    )

    return azure_parser
