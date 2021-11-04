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

from bs4 import BeautifulSoup  # type: ignore
from typing import Tuple


def get_encrypted_pfx(config: str) -> Tuple[str, str]:
    """Using BeautifulSoup, grab the EncryptedPfx and Server Issuer.

    Arguments:
        configuration: ADFS config data

    Returns:
        tuple of EncryptedPfx and Server Issuer strings
    """
    bs = BeautifulSoup(config, features="lxml")
    encPfx = (
        bs.body.servicesettingsdata.securitytokenservice.signingtoken.encryptedpfx.text
    )
    server = bs.body.servicesettingsdata.securitytokenservice.issuer.address.text
    return (encPfx, server)
