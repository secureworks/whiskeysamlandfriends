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

import hmac
import base64
import logging
import hashlib
from uuid import uuid4
from typing import Dict, Any
from xml.etree import ElementTree
from Crypto.Cipher import ARC4  # type: ignore
from pyasn1.codec.der import decoder  # type: ignore
from ticketsplease.modules.adfs.envelope.utils import (
    send_envelope,
    NAMESPACES,
)


class RST_ENVELOPE:
    def _create_rst_envelope(
        self,
        server: str,
        KerberosTicket: str,
    ) -> str:
        """Build RST Envelope.

        Arguments:
            server: ip_address|hostname of ADFS server
            KerberosTicket: base64 encoded ticket

        References:
            https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L517
        """
        envelope = f"""
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing">
	        <s:Header>
		        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
		        <a:MessageID>urn:uuid:{uuid4()}</a:MessageID>
		        <a:ReplyTo>
			        <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
		        </a:ReplyTo>
		        <a:To s:mustUnderstand="1">http://{server}/adfs/services/policystoretransfer</a:To>
	        </s:Header>
	        <s:Body>
		        <t:RequestSecurityToken Context="uuid-{uuid4()}" xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">
			        <t:TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</t:TokenType>
			        <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
			        <t:KeySize>256</t:KeySize>
			        <t:BinaryExchange ValueType="http://schemas.xmlsoap.org/ws/2005/02/trust/spnego" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{KerberosTicket}</t:BinaryExchange>
		        </t:RequestSecurityToken>
	        </s:Body>
        </s:Envelope>
        """
        # Strip the trailing spaces when returning, but leave leading
        # whitespace as Microsoft parsing is particular
        return envelope.rstrip()

    def _parse_gss_wrapper(
        self,
        data: bytes,  # proofToken
        subkey: bytes,  # sessionKey
        sequenceNumber: bytes,
        encryptionType: int = 23,  # RC4_HMAC
        direction: str = "Initiator",
    ) -> bytes:
        """Parses GSS_Wrap and returns the encrypted data part

        Arguments:
            data: proofToken from RST response
            subkey: session key
            sequenceNumber: sequence number
            encryptionType: type of encryption (always RC4_HMAC)
            direction: (always Initiator)

        Returns:
            parsed gss wrapper bytes
        """
        logging.info("\tParsing GSS Wrapper")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L218
        # Generate the sequence number from the given integer and add "direction" bytes
        # This will always be Initiator for our purposes
        SND_SEQ = sequenceNumber.to_bytes(4, "big")
        if direction == "Initiator":
            SND_SEQ += b"\xff\xff\xff\xff"
        else:
            SND_SEQ += b"\x00\x00\x00\x00"

        if len(data) <= 0:
            raise ValueError("invalid GSS Wrapper data")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L294
        # Get object identifier (OID)
        tokLen = data[1]
        oidLen = data[3]
        oid = data[4 : (4 + oidLen)]  # Remove -1 to account for Python exclusivity
        s = 4 + oidLen

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L300
        # Save the header for checksum calculation
        TOKEN_HEADER = data[s : (s + 8)]  # Add 1 to account for Python exclusivity

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L303
        # Get the token header information
        #   Add 1 to account for Python exclusivity
        TOK_ID = data[s : (s + 2)]
        s += 2  # Increment
        SGN_ALG = data[s : (s + 2)]
        s += 2  # Increment
        SEAL_ALG = data[s : (s + 2)]
        s += 2  # Increment
        FILLER = data[s : (s + 2)]
        s += 2  # Increment

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L309
        # Extract token information
        #   Add 1 to account for Python exclusivity
        encSND_SEQ = data[s : (s + 8)]
        s += 8  # Increment
        SGN_CHKSUM = data[s : (s + 8)]
        s += 8  # Increment
        encSGN_Confounder = data[s : (s + 8)]
        s += 8  # Increment
        encData = data[s:]

        logging.debug("\tValidating extracted data from GSS Wrapper")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L316
        # Validation
        # Token id should be 0x0102
        if int.from_bytes(TOK_ID, "little") != 0x102:
            raise ValueError(f"Unknown TOKEN_ID {TOK_ID}, expected 258 (0x102 -> 258)")
        # Signing algorithm should be HMAC 0x0011
        if int.from_bytes(SGN_ALG, "little") != 0x11:
            raise ValueError(f"Unknown SGN_ALG  {SGN_ALG}, expected HMAC (0x11 -> 17)")
        # Encryption algorithm should be RC4 0x0010
        if int.from_bytes(SEAL_ALG, "little") != 0x10:
            raise ValueError(f"Unknown SEAL_ALG {SEAL_ALG}, expected RC4 (0x10 -> 16)")

        logging.info("\tGenerating signature and decryption keys")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L332
        # Generate signature key by calculating MD5 HMAC from "signaturekey" + 0x00
        # using the session key
        kSign = hmac.new(
            subkey,
            msg=b"signaturekey\x00",
            digestmod=hashlib.md5,
        ).digest()

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L335
        # Generate decryption keys
        kLocal = b""
        for i in range(len(subkey)):
            kLocal += bytes([(subkey[i] ^ 0xF0)])

        kSeq = hmac.new(
            subkey,
            msg=b"\x00\x00\x00\x00",
            digestmod=hashlib.md5,
        ).digest()
        kSeq = hmac.new(
            kSeq,
            msg=SGN_CHKSUM,
            digestmod=hashlib.md5,
        ).digest()

        kCrypt = hmac.new(
            kLocal,
            msg=b"\x00\x00\x00\x00",
            digestmod=hashlib.md5,
        ).digest()
        kCrypt = hmac.new(
            kCrypt,
            msg=SND_SEQ[0:4],
            digestmod=hashlib.md5,
        ).digest()

        logging.info("\tDecrypting Sequence Number")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L348
        # Decrypt sequence number
        decSND_SEQ_cipher = ARC4.new(kSeq)
        decSND_SEQ = decSND_SEQ_cipher.decrypt(encSND_SEQ)

        logging.debug(f"\tValidating decrypted sequence number")

        if decSND_SEQ != SND_SEQ:
            raise ValueError("Sequence number mismatch!")

        logging.debug(f"\tSequence Number: {decSND_SEQ}")
        logging.info(f"\tDecrypting data")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L355
        # Decrypt data
        decSGN_Confounder_cipher = ARC4.new(kCrypt)
        decSGN_Confounder = decSGN_Confounder_cipher.decrypt(encSGN_Confounder)

        decData_cipher = ARC4.new(kCrypt)
        decData = decData_cipher.decrypt(decSGN_Confounder + encData)
        decData = decData[8:]

        # NOTE: These don't actually appear to be used in AADInternals
        # decSGN_CHKSUM_cipher = ARC4.new(kCrypt)
        # decSGN_CHKSUM = decSGN_CHKSUM_cipher.decrypt(None)  # encSGN_CHKSUM

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L361
        # Calculate MD5 checksum: Salt + header + confounder + data
        SGN_CHKSUM2 = hashlib.md5(
            b"\x0d\x00\x00\x00" + TOKEN_HEADER + decSGN_Confounder + decData
        ).digest()
        SGN_CHKSUM2 = hmac.new(
            kSign,
            msg=SGN_CHKSUM2,
            digestmod=hashlib.md5,
        ).digest()[0:8]

        logging.debug(f"\tValidating decrypted data checksum")

        if SGN_CHKSUM != SGN_CHKSUM2:
            raise ValueError("Invalid checksum!")

        return decData

    def _parse_rst_envelope(
        self,
        envelope: bytes,
        cipher: "impacket.krb5.crypto._RC4",  # type: ignore
        sessionKey: "impacket.krb5.crypto.Key",  # type: ignore
    ) -> Dict[str, bytes]:
        """Parse the RST response envelope.

        Arguments:
            envelope: RST response envelope
            cipher: KRB_TGT cipher object
            sessionKey: KRB_TGT session key object

        Returns:
            parsed RST envelope (context, key, key identifier)
        """
        try:
            # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L568
            # Extract information from the RSTR by parsing the XML, but because it's
            # a SOAP object, we need to access the data via namespace handling.
            tree = ElementTree.fromstring(envelope)

            krb_response = base64.b64decode(
                tree.find(".//t:BinaryExchange", NAMESPACES["t"]).text
            )
            proofToken = base64.b64decode(
                tree.find(".//e:CipherValue", NAMESPACES["e"]).text
            )
            # fmt: off
            # [0][0] -> <SecurityContextToken><Identifier>
            #   Split(':') -> urn:uuid:ec82506b-35ea-44be-a841-9f0d0f175c25
            keyIdentifier = tree.find(".//t:RequestedSecurityToken", NAMESPACES["t"])[0][0].text.split(":")[2]
            # [0] -> <SecurityContextToken>
            #   Get the URL of the namespace for `u` to build the attrib key:
            #     {ns_url}Id
            context = tree.find(".//t:RequestedSecurityToken", NAMESPACES["t"])[0]
            context = context.attrib["{%s}Id" % NAMESPACES["u"]["u"]]
            # fmt: on
        except Exception as e:
            logging.error(str(e))
            raise TypeError("server responded with malformed RST envelope") from e

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L574
        # ASN.1 decode the ticket response object
        ticket = decoder.decode(krb_response)[0]

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L577
        # Get the encrypted kerberos ticket
        encKRB = bytes(ticket[2])

        # NOTE: This is a super hacky way to do this, but the pyasn1 decoder
        #       doesn't seem to like to play with the `Application 0` tag that
        #       is wrapping the AP_REP.
        # First, we find where our AP_REP starts via HEX
        ap_rep_index = encKRB.find(b"\x6f")
        # Strip the headers and grab just the AP_REP tag
        encKRB = encKRB[ap_rep_index:]

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L578
        # Decode and get the octet string value which will hold our ticket
        encKRB = decoder.decode(encKRB)[0]
        encKRB = encKRB[2][1]  # Octet string value

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L581
        # Key Usage 12
        #   AP-REP encrypted part (includes application session
        #   subkey), encrypted with the application session key
        #   (Section 5.5.2)
        decKRB = cipher.decrypt(sessionKey, 12, encKRB)
        decKRB = decoder.decode(decKRB)[0]

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L586
        # After decrypting the AP_REP, grab the data to begin parsing the signature
        # data
        sequenceNumber = int(decKRB[3])
        subkey = bytes(decKRB[2][1])
        encryptionType = int(decKRB[2][0])

        logging.debug(f"\tSubkey:        {base64.b64encode(subkey)}")
        logging.debug(f"\tSequence num:  {sequenceNumber}")

        # Extract the key from the proof token
        # Make sure to trim off any trailing data past 32 bytes
        securityKey = self._parse_gss_wrapper(
            self,
            data=proofToken,
            subkey=subkey,
            sequenceNumber=sequenceNumber,
            encryptionType=encryptionType,
            direction="Initiator",
        )[0:32]

        logging.debug(f"\tSecurity key:  {base64.b64encode(securityKey)}")
        logging.debug(f"\tContext:       {context}")
        logging.debug(f"\tIdentifier:    {keyIdentifier}")

        # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L601
        # Construct the return value
        retVal = {
            "Context": context,
            "Key": securityKey,
            "Identifier": keyIdentifier,
        }

        return retVal

    @classmethod
    def run(
        cls,
        adfs_host: str,
        ticket_base64: str,
        cipher: "impacket.krb5.crypto._RC4",  # type: ignore
        sessionKey: "impacket.krb5.crypto.Key",  # type: ignore
    ) -> Dict[str, Any]:
        """Generate and send an RST (RequestSecurityToken) envelope
        to the target ADFS server. Receive the RST response and parse
        the message for the context, key, and key identifier.

        Arguments:
            adfs_host: target ADFS server
            ticket_base64: Base64 encoded KRB_TGT ticket
            cipher: KRB_TGT cipher object
            sessionKey: KRB_TGT session key object

        Returns:
            dictionary of parsed RST response data (context, key,
            key identifier)
        """
        logging.info(f"[ * ] Building and sending RST envelope to the ADFS server")

        # Build the RST envelope to request the configuration
        envelope = cls._create_rst_envelope(cls, adfs_host, ticket_base64)

        logging.debug(f"\tRST Envelope:\n{envelope}")

        # Send the RST envelope
        response = send_envelope(adfs_host, envelope)

        logging.debug(f"\tRST Response Status: {response}")
        logging.debug(f"\tRST Response:\n{response.content}")

        if response.status_code == 200:
            logging.info(f"[ * ] Parsing RST envelope response")

            rst_data = cls._parse_rst_envelope(
                cls,
                response.content,
                cipher,
                sessionKey,
            )
        else:
            raise ValueError(f"Bad response from ADFS server: {response.status_code}")

        return rst_data
