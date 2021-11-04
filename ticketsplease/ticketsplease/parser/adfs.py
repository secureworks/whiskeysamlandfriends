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


def adfs_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `adfs` module"""
    example_usage = """example usage:

    ticketsplease adfs --adfs-host 10.10.10.10 --krb-key '...' --krb-ticket '...'
    """

    adfs_parser = subparsers.add_parser(
        "adfs",
        description="Remotely pull down the ADFS Configuration of a target ADFS server",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    adfs_parser.add_argument(
        "--adfs-host",
        type=str,
        help="Target ADFS server to retrieve the configuration from.",
        required=True,
    )
    adfs_parser.add_argument(
        "--krb-ticket",
        type=str,
        help="Base64 encoded Kerberos ticket.",
        required=True,
    )
    adfs_parser.add_argument(
        "--krb-key",
        type=str,
        help="Base64 encoded key used when generating the provided Kerberos ticket.",
        required=True,
    )
    adfs_parser.add_argument(
        "--output",
        action="store_true",
        help="Write the ADFS config to 'config.bin'.",
    )

    return adfs_parser
