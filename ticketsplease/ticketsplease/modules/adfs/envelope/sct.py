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

import base64
import logging
from os import urandom
from uuid import uuid4
from typing import Dict
from xml.etree import ElementTree
from ticketsplease.modules.adfs.envelope.utils import (
    NAMESPACES,
    send_envelope,
    get_psha1,
    derive_wstrustkey,
    decrypt_wstrust_cipherdata,
    create_soap_envelope,
)


class SCT_ENVELOPE:
    def _create_sct_envelope(
        self,
        key: bytes,
        clientSecret: bytes,
        context: bytes,
        keyIdentifier: bytes,
        server: str,
    ):
        """Build a SCT enevlope.

        Arguments:
            key: security key from parsed RSTR
            clientSecret: generated random bytes
            context: security context from parsed RSTR
            keyIdentifier: key identifier from parsed RSTR
            server: ip_address|hostname of ADFS server

        Returns:
            SCT envelope
        """
        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L627
        payload = f'<t:RequestSecurityToken xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:Entropy><t:BinarySecret Type="http://schemas.xmlsoap.org/ws/2005/02/trust/Nonce" u:Id="uuid-{uuid4()}">{base64.b64encode(clientSecret).decode()}</t:BinarySecret></t:Entropy><t:KeySize>256</t:KeySize></t:RequestSecurityToken>'
        action = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT"

        envelope = create_soap_envelope(
            key,
            context,
            keyIdentifier,
            server,
            payload,
            action,
        )

        return envelope

    def _parse_sct_envelope(
        self,
        envelope: bytes,
        key: bytes,
        clientSecret: bytes,
    ) -> str:
        """Parse the SCT response envelope.

        Arguments:
            envelope: SCT response envelope
            cipher: KRB_TGT cipher object
            sessionKey: KRB_TGT session key object

        Returns:
            parsed SCT envelope (context, key, key identifier)
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
            raise TypeError("server responded with malformed SCT envelope") from e

        derivedKey = derive_wstrustkey(key, nonce1, 32)

        logging.debug(f"\tNonce:         {base64.b64encode(nonce1)}")
        logging.debug(f"\tDerived key:   {base64.b64encode(derivedKey)}")

        logging.info("\tDecrypting WSTrust Cipher Text")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L727
        # Decrypt the cipher data
        bPlainText = decrypt_wstrust_cipherdata(cipher1, derivedKey)

        logging.debug(f"\tDecrypted SCT Data:\n{bPlainText.decode().strip()}\n")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L651
        # Now parse the decrypted data from the outter SCT envelope
        try:
            tree = ElementTree.fromstring(bPlainText)
        except Exception as e:
            logging.error(str(e))
            logging.error(f"invalid xml:\n{bPlainText}")
            raise TypeError("failed to parse decrypted SCT envelope data") from e

        token = tree.find(".//t:BinarySecret", NAMESPACES["t"]).text

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L653
        serverSecret = base64.b64decode(token)
        computedKey = get_psha1(clientSecret, serverSecret, 32)

        # fmt: off
        # https://github.com/Gerenios/AADInternals/blob/c255cd66a3731c32cfbdf9fdb17f2b03c7665b72/ADFS_utils.ps1#L656
        context = tree.find(".//t:RequestedSecurityToken", NAMESPACES["t"])[0]
        context = context.attrib["{%s}Id" % NAMESPACES["u"]["u"]]
        keyIdentifier = tree.find(".//t:RequestedSecurityToken", NAMESPACES["t"])[0][0].text.split(":")[2]
        # fmt: on

        logging.debug(f"\tServer secret: {base64.b64encode(serverSecret)}")
        logging.debug(f"\tComputed key:  {base64.b64encode(computedKey)}")
        logging.debug(f"\tContext:       {context}")
        logging.debug(f"\tIdentifier:    {keyIdentifier}")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L665
        # Construct the return value
        retVal = {
            "Context": context,
            "Key": computedKey,
            "Identifier": keyIdentifier,
        }

        return retVal

    @classmethod
    def run(
        cls,
        adfs_host: str,
        rstr: Dict[str, bytes],
    ):
        """Generate and send an SCT envelope to the target ADFS server.
        Receive the SCT response and parse the message for the context,
        key, and key identifier.

        Arguments:
            adfs_host: target ADFS server
            rsts: parsed RST response object

        Returns:
            dictionary of parsed SCT response data (context, key,
            key identifier)
        """
        logging.info(f"[ * ] Building and sending SCT envelope to the ADFS server")

        clientSecret = urandom(32)

        # Build the SCT envelope to request the configuration
        sct_envelope = cls._create_sct_envelope(
            cls,
            rstr["Key"],
            clientSecret,
            rstr["Context"],
            rstr["Identifier"],
            adfs_host,
        )

        logging.debug(f"\tSCT Envelope:\n{sct_envelope.strip()}")

        # Send the SCT envelope
        response = send_envelope(adfs_host, sct_envelope)

        logging.debug(f"\tRST Response Status: {response}")
        logging.debug(f"\tRST Response:\n{response.content}")

        if response.status_code == 200:
            logging.info(f"[ * ] Parsing SCT envelope response")

            sct_data = cls._parse_sct_envelope(
                cls,
                response.content,
                rstr["Key"],
                clientSecret,
            )
        else:
            raise ValueError(f"Bad response from ADFS server: {response.status_code}")

        return sct_data
