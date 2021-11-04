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

import struct
import logging
import datetime
from os import urandom
from random import randint
from binascii import unhexlify
from pyasn1.type import univ, namedtype  # type: ignore
from pyasn1.codec.der import encoder  # type: ignore
from pyasn1.type.univ import noValue  # type: ignore
from impacket.krb5 import constants  # type: ignore
from impacket.krb5.asn1 import AP_REQ, Authenticator, seq_set, _sequence_component, AuthorizationData, Int32  # type: ignore
from impacket.krb5.types import Ticket, Principal, KerberosTime  # type: ignore
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, ASN1_OID, asn1encode, ASN1_AID  # type: ignore
from impacket.krb5.gssapi import (  # type: ignore
    KRB5_AP_REQ,
    CheckSumField,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
)


# Here, we are going to create a custom AuthorizationData structure that will allow us
# to capture data in a top-level sequence (AuthorizationData() is a base class of univ.SequenceOf
# where we want to work directly with a single Sequence).
# Via: https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/asn1.py#L140
#      https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L707
class AuthorizationDataSequence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("ad-type", 0, Int32()),
        _sequence_component("ad-data", 1, univ.OctetString()),
    )


class KRB_AP_REQ:
    """Custom class to generate a KRB_AP_REQ ticket from a given TGT that
    we retrieve from our custom Impacket TICKETER script."""

    def _gen_authorization_data(
        self,
        spn: str,
        domain: str,
    ) -> bytes:
        """Build the authorization data object for the Authenticator.
        A lot of this is manual based on the actual structure built in AADInternals.

        References:
            https://github.com/morRubin/AzureADJoinedMachinePTC/blob/master/AzureADPTC/kerberos/impacketTGS.py#L283
            https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L737

        Arguments:
            spn: <service>/<server> (i.e. host/sts.company.com)
            domain: <server> (i.e. company.com)

        Returns:
            authorization_data bytes
        """
        # fmt: off

        # Build the AD Negotiation data set.
        #   AdETypeNegotiation -> RC4_HMAC_NT
        #   0x17 -> RC4_HMAC_NT
        # Since we can't build an ASN.1 sequence without a#,
        # we are just going to hard code this sequence
        # 
        # 300f a004 0202 0081 a107 0405 3003 0201
        # 17
        # ----------------------------------------
        # 30 0f                 - SEQ
        #   a0 04 02 02 00 81   - INT: 0x81
        #   a1 07 04 05         - OCT STRING
        #       30 03 02 01 17  - SEQ -> INT: 0x17
        neg_type = b"\x30\x03\x02\x01\x17"
        negotiation_type_data_seq = AuthorizationDataSequence()
        negotiation_type_data_seq["ad-type"] = 0x81
        negotiation_type_data_seq["ad-data"] = neg_type

        # Build the Restriction Types data set
        # 
        # 303f a004 0202 008d a137 0435 3033 3031
        # a003 0201 00a1 2a04 2800 0000 0000 1000
        # 00f3 cd6a f91c c2b1 32fd fbf1 6349 7585
        # 5e62 4ba4 9675 639e 351a 919e 3028 b9e0
        # 00
        # ----------------------------------------
        # 30 3f                                  - SEQ
        #   a0 04 02 02 00 8d                    - INT: 0x8D
        #   a1 37 04 35                          - OCT STRING
        #     30 33                              - SEQ
        #       30 31                            - SEQ
        #         a0 03 02 01 00                 - INT: 0x00
        #         a1 2a 04 28                    - OCT STRING
        #           00 00 00 00 00 10 00 00...   - re_data
        re_data = b"\x00\x00\x00\x00\x00\x10\x00\x00" + urandom(32)
        restriction_data = AuthorizationData()
        restriction_data[0]["ad-type"] = 0  # const
        restriction_data[0]["ad-data"] = re_data

        kerb_auth_data_token_restrictions = AuthorizationDataSequence()
        kerb_auth_data_token_restrictions["ad-type"] = 0x8D  # 141
        kerb_auth_data_token_restrictions["ad-data"] = encoder.encode(restriction_data)

        # Build the KerbLocal data set
        # 
        # 301a a004 0202 008e a112 0410 bc20 16eb
        # a5f8 8b2a df78 2b94 7456 bd72
        # ----------------------------------------
        # 30 1a                            - SEQ
        #   a0 04 02 02 00 8e              - INT: 0x8E
        #   a1 12 04 10                    - OCT STRING
        #       bc 20 16 eb a5 f8 8b 2a... - urandom()
        kerb_local_data = AuthorizationDataSequence()
        kerb_local_data["ad-type"] = 0x8E
        kerb_local_data["ad-data"] = urandom(16)

        # Build the KerbApOptions data set
        #   ChannelBindingSupported
        # 
        # 300e a004 0202 008f a106 0404 0040 0000
        # ----------------------------------------
        # 30 0e                 - SEQ
        #   a0 04 02 02 00 8f   - INT: 0x8F
        #   a1 06 04 04         - OCT STRING
        #       00 40 00 00     - \x00\x40\x00\x00
        binding_data = AuthorizationDataSequence()
        binding_data["ad-type"] = 0x8F
        binding_data["ad-data"] = b"\x00\x40\x00\x00"

        # Build the KerbServiceTarget data set
        # 
        # 304a a004 0202 0090 a142 0440 6800 6f00
        # 7300 7400 2f00 7300 7400 7300 2e00 6300
        # 6f00 6d00 7000 6100 6e00 7900 2e00 6300
        # 6f00 6d00 4000 6300 6f00 6d00 7000 6100
        # 6e00 7900 2e00 6300 6f00 6d00
        # ----------------------------------------
        # 30 4a                                - SEQ
        #   a0 04 02 02 00 90                  - INT: 0x90
        #   a1 42 04 40 68                     - OCT STRING
        #       00 6f 00 73 00 74 00 2f 00...  - spn@domain -> UTF-16LE (null padded)
        kerb_service_target_data = AuthorizationDataSequence()
        kerb_service_target_data["ad-type"] = 0x90
        kerb_service_target_data["ad-data"] = f"{spn}@{domain}".encode("utf-16le")

        # Now, wrap the above data sets in a sequence (top down).
        # Since we can't build an ASN.1 sequence without a#, we
        # are just going to hard code the sequence and manually
        # calculate the data length.
        # 
        # 3081 XX ....
        # ----------------------------------------
        # 30 81     -- SEQ
        #   XX      -- LEN
        #   .. ..   -- COMBINED DATA
        auth_data = (
            encoder.encode(negotiation_type_data_seq)
            + encoder.encode(kerb_auth_data_token_restrictions)
            + encoder.encode(kerb_local_data)
            + encoder.encode(binding_data)
            + encoder.encode(kerb_service_target_data)
        )
        auth_data_len = hex(len(auth_data))[2:]  # Strip `0x`
        auth_data_len = unhexlify(auth_data_len)  # Convert to `\x`
        authorization_data = b"\x30\x81" + auth_data_len + auth_data

        # fmt: on
        return authorization_data

    def _gen_authenticator(
        self,
        tgt: "impacket.krb5.asn1.TGS_REP",  # type: ignore
        spn: str,
        domain: str,
    ) -> bytes:
        """Build Authenticator object for AP_REQ based on the TGT.

        Arguments:
            tgt: KRB_TGT object
            spn: <service>/<server> (i.e. host/sts.company.com)
            domain: <server> (i.e. company.com)

        Returns:
            encoded Authenticator bytes
        """

        # Initialize a new AP_REQ Authenticator instance
        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5

        # Add crealm
        authenticator["crealm"] = str(tgt["crealm"])

        # Add cname
        clientName = Principal()
        clientName.from_asn1(tgt, "crealm", "cname")
        seq_set(authenticator, "cname", clientName.components_to_asn1)

        # We need to add this custom flag as it's not present in Impacket, but
        # the AADInternals flags equate to `0x203e` and ours was `0x103e`
        #   0x103e == 4158
        #   0x203e == 8254
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L684
        GSS_C_IDENTIFY_FLAG = 0x2000  # 8192

        # Add checksum
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L657
        #      https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/kerberosv5.py#L654
        # We are swapping out the `GSS_C_DCE_STYLE` flag for `GSS_C_IDENTIFY_FLAG` so
        # that we can match the final value of AADInternals
        chkField = CheckSumField()
        chkField["Lgth"] = 16
        chkField["Flags"] = (
            GSS_C_CONF_FLAG
            | GSS_C_INTEG_FLAG
            | GSS_C_SEQUENCE_FLAG
            | GSS_C_REPLAY_FLAG
            | GSS_C_MUTUAL_FLAG
            | GSS_C_IDENTIFY_FLAG
        )
        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003  # KRBv5  # 32771
        authenticator["cksum"]["checksum"] = chkField.getData()

        # Add timestamps
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L695
        # Turns out, according to AADInternals, `cusec` can just be 1
        authenticator["cusec"] = 0x01  # now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(datetime.datetime.utcnow())

        # Add subkey
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L701
        authenticator["subkey"] = noValue
        authenticator["subkey"]["keytype"] = 0x17
        authenticator["subkey"]["keyvalue"] = urandom(16)

        # Add sequence number
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L705
        #      https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/kerberosv5.py#L663
        # Generate a random 10 digit value that starts with `1`
        seq_number = "1" + "".join(["{}".format(randint(0, 9)) for _ in range(0, 9)])
        authenticator["seq-number"] = int(seq_number)  # 1497574779

        logging.info(f"\tGenerating Authenticator authorization data")

        # Generate Authorization Data object
        authorization_data = self._gen_authorization_data(self, spn, domain)

        # Add authorization data
        authenticator["authorization-data"][0]["ad-type"] = 0x01
        authenticator["authorization-data"][0]["ad-data"] = authorization_data

        if logging.getLogger().level == logging.DEBUG:
            logging.debug("Authenticator")
            print(authenticator.prettyPrint())
            print("\n")

        # Encode the Authenticator
        encodedAuthenticator = encoder.encode(authenticator)

        return encodedAuthenticator

    def _wrap_spnego(self, apReq: AP_REQ) -> SPNEGO_NegTokenInit:
        """Wrap the KRB_AP_REQ in an SPNEGO NegTokenInit

        References:
            https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/kerberosv5.py#L624

        Arguments:
            apReq: KRB_AP_REQ data to be wrapped

        Returns:
            new SPNEGO_NegTokenInit object
        """
        blob = SPNEGO_NegTokenInit()

        # OID's
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L793
        blob["MechTypes"] = [
            TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            TypesMech["KRB5 - Kerberos 5"],
            TypesMech["NEGOEX - SPNEGO Extended Negotiation Security Mechanism"],
            TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"],
        ]

        blob["MechToken"] = (
            # 0x60 -> Start of NegTokenInit packet
            struct.pack("B", ASN1_AID)
            + asn1encode(
                # 0x06 -> Start of OID
                struct.pack("B", ASN1_OID)
                + asn1encode(TypesMech["KRB5 - Kerberos 5"])
                + KRB5_AP_REQ  # struct.pack('<H', 0x1) == (0x01, 0x00) == False
                + encoder.encode(apReq)
            )
        )

        return blob

    @classmethod
    def run(
        cls,
        tgt: "impacket.krb5.asn1.TGS_REP",  # type: ignore
        cipher: "impacket.krb5.crypto._RC4",  # type: ignore
        sessionKey: "impacket.krb5.crypto.Key",  # type: ignore
        spn: str,
        domain: str,
    ) -> bytes:
        """Build KRB_AP_REQ message.
        Publicly accessible class method to generate an KRB_AP_REQ.

        References:
            https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py#L299

        Arguments:
            tgt: KRB_TGT object
            cipher: KRB_TGT cipher object
            sessionKey: KRB_TGT sessionKey object
            spn: <service>/<server> (i.e. host/sts.company.com)
            domain: <server> (i.e. company.com)

        Returns:
            KRB_AP_REQ bytes
        """
        logging.info(f"[ * ] Building KRB_AP_REQ message")

        # Grab the ticket from the TGT
        ticketTGT = Ticket()
        ticketTGT.from_asn1(tgt["ticket"])

        # Initialize a new AP_REQ
        apReq = AP_REQ()
        apReq["pvno"] = 5
        apReq["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        # Specify the AP_REQ flags
        # Via: https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L812
        #      https://github.com/SecureAuthCorp/impacket/blob/master/impacket/krb5/constants.py#L25
        # Specify `2` to flip the third index of the flags to `1`
        # so that the final bytes match AADInternals
        opts = [2]  # KERB_VALINFO
        apReq["ap-options"] = constants.encodeFlags(opts)

        # Add encrypted TGT
        # https://github.com/Gerenios/AADInternals/blob/master/Kerberos.ps1#L840
        seq_set(apReq, "ticket", ticketTGT.to_asn1)

        logging.info(f"\tGenerating KRB_AP_REQ Authenticator")

        # Generate an Authenticator data set
        encodedAuthenticator = cls._gen_authenticator(cls, tgt, spn, domain)

        logging.info(
            f"\tEncrypting the KRB_AP_REQ with key: {sessionKey.contents.decode()}"
        )

        # Encrypt the Authenticator
        # Key Usage 11
        #   AP-REQ Authenticator (includes application authenticator
        #   subkey), encrypted with the application session key
        #   (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(
            sessionKey, 11, encodedAuthenticator, None
        )

        # Add the encrypted Authenticator
        apReq["authenticator"] = noValue
        apReq["authenticator"]["etype"] = cipher.enctype
        apReq["authenticator"]["cipher"] = encryptedEncodedAuthenticator

        logging.info(f"[ * ] Building KRB_SPNEGO message")

        # Wrap the AP_REQ in SPNEGO NegTokenInit
        blob = cls._wrap_spnego(cls, apReq)

        ap_req_message = blob.getData()

        logging.debug(f"\tKRB_AP_REQ Message Size: {len(ap_req_message)} bytes")
        logging.debug(f"\tKRB_AP_REQ Message (HEX):\n{ap_req_message.hex()}")

        # Return the raw ticket data
        return ap_req_message
