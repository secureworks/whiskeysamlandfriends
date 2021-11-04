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


def dcsync_args(subparsers: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """Parse command line args for `dcsync` module"""
    example_usage = """example usage:

    ticketsplease dcsync --domain company.com --target-user user --username admin --password password --dc-ip 10.10.10.10
    """

    dcsync_parser = subparsers.add_parser(
        "dcsync",
        description="Retrieve SID and password hash via DCSync for a target user",
        epilog=example_usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    dcsync_parser.add_argument(
        "--dc-ip",
        type=str,
        help="IP address of the target Domain Controller.",
        required=True,
    )
    dcsync_parser.add_argument(
        "--domain",
        type=str,
        help="Target domain the Domain Controller is in (i.e. company.com).",
        required=True,
    )
    dcsync_parser.add_argument(
        "--target-user",
        type=str,
        help="Target user to retrieve the SID and password hash for.",
        required=True,
    )
    dcsync_parser.add_argument(
        "--username",
        type=str,
        help="Username to perform DCSync operations with.",
        required=True,
    )
    password_group = dcsync_parser.add_mutually_exclusive_group()
    password_group.add_argument(
        "--password",
        type=str,
        help="Password of the account to perform DCSync operations with.",
    )
    password_group.add_argument(
        "--password-hash",
        type=str,
        help="Password hash of the account to perform DCSync operations with (supersedes --password).",
    )

    return dcsync_parser
