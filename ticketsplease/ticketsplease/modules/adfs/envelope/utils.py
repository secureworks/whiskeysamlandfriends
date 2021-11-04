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
import hashlib
import logging
import requests
import datetime
from os import urandom
from uuid import uuid4
from typing import Union
from Crypto.Cipher import AES  # type: ignore
from Crypto.Util.Padding import pad  # type: ignore


# Create SOAP namespace based on test responses retrieved from the ADFS
# server
NAMESPACES = {
    "c": {
        "c": "http://schemas.xmlsoap.org/ws/2005/02/sc",
    },
    "s": {
        "s": "http://www.w3.org/2003/05/soap-envelope",
    },
    "t": {
        "t": "http://schemas.xmlsoap.org/ws/2005/02/trust",
    },
    "a": {
        "a": "http://www.w3.org/2005/08/addressing",
    },
    "e": {
        "e": "http://www.w3.org/2001/04/xmlenc#",
    },
    "i": {
        "i": "http://www.w3.org/2001/XMLSchema-instance",
    },
    "o": {
        "o": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    },
    "u": {
        "u": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    },
}

# ==============================
#  Encryption support functions
# ==============================

# https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L381
def get_psha1(
    secret: bytes,
    seed: bytes,
    _bytes: int = 32,
) -> bytes:
    psha1 = b""
    a = seed
    p = 0

    while p < _bytes:
        a = hmac.new(
            secret,
            msg=a,
            digestmod=hashlib.sha1,
        ).digest()
        psha1 += hmac.new(
            secret,
            msg=(a + seed),
            digestmod=hashlib.sha1,
        ).digest()
        p += len(a)

    return psha1[0:_bytes]


# https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L491
def derive_wstrustkey(
    key: bytes,
    nonce: bytes,
    bytes: int = 32,
) -> bytes:
    label = b"WS-SecureConversationWS-SecureConversation"
    return get_psha1(key, (label + nonce), bytes)


# https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L453
def encrypt_wstrust_cipherdata(
    plaintext: str,
    key: bytes,
) -> bytes:
    initialVector = urandom(16)
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=initialVector,
    )
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size, style="pkcs7"))
    # ct = base64.b64encode(ct_bytes).decode("utf-8")

    return initialVector + ct_bytes


# https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L415
def decrypt_wstrust_cipherdata(
    ciphertext: str,
    key: bytes,
) -> bytes:
    initialVector = ciphertext[0:16]
    encText = ciphertext[16:]
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv=initialVector,
    )
    pt_bytes = cipher.decrypt(encText)

    return pt_bytes


# https://github.com/Gerenios/AADInternals/blob/master/CommonUtils.ps1#L1221
def get_digest(data: Union[str, bytes]) -> bytes:
    return hashlib.sha1(data.encode()).digest()


# ====================================
#  Envelope request support functions
# ====================================


def send_envelope(
    adfs_host: str,
    envelope: str,
) -> requests.Response:
    """Send an envelope to the target ADFS server.

    Arguments:
        adfs_host: target ADFS server
        envelope: envelope to send

    Returns:
        ADFS server response
    """
    url = f"http://{adfs_host}/adfs/services/policystoretransfer"
    headers = {"Content-Type": "application/soap+xml"}
    response = None
    try:
        response = requests.post(url, data=envelope, headers=headers)
    except Exception as e:
        logging.error(e)
    return response


def create_soap_envelope(
    key: bytes,
    context: bytes,
    keyIdentifier: bytes,
    server: str,
    payload: str,
    action: str,
) -> str:
    """Build ADFS Soap Envelope.

    Arguments:
        key: security key
        context: security context
        keyIdentifier: key identifier
        server: ip_address|hostname of ADFS server
        payload: paylaod
        action: action

    References:
        https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L806
    """
    # Implement `Create-ADFSSoapEnvelope` function
    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L806
    # Set some required variables
    STSContext = context  # uuid-<UUID>
    messageID = uuid4()
    STIdentifier = keyIdentifier  # <UUID>
    TSIdentifier = uuid4()
    now = datetime.datetime.utcnow()
    exp = now + datetime.timedelta(minutes=5)
    created = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = exp.strftime("%Y-%m-%dT%H:%M:%SZ")

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L836
    # Create nonce and derive keys for signing and encrypting
    nonce0 = urandom(16)
    nonce1 = urandom(16)
    signingKey = derive_wstrustkey(key, nonce0, 24)
    encryptionKey = derive_wstrustkey(key, nonce1, 32)

    logging.debug(f"Signing Key:    {signingKey}")
    logging.debug(f"Encryption Key: {encryptionKey}")

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L844
    # Create the SOAP request and encrypt it
    cipherText = base64.b64encode(
        encrypt_wstrust_cipherdata(payload.encode(), encryptionKey)
    ).decode()

    logging.debug(f"Cipher Text:    {cipherText}")

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L852
    # Create required xml elements.
    # Based on AADInternals notes, Microsoft parsing on the backend requires
    # strict XML data -- these data sets should not contain any white space.
    # Changing the order of any elements will break the signature as all XML
    # elements are canonicalized with C14N exclusive.
    # Create a body element
    xBody = f'<s:Body xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_2"><e:EncryptedData xmlns:e="http://www.w3.org/2001/04/xmlenc#" Id="_3" Type="http://www.w3.org/2001/04/xmlenc#Content"><e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"></e:EncryptionMethod><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference URI="#_1" ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/dk"></o:Reference></o:SecurityTokenReference></KeyInfo><e:CipherData><e:CipherValue>{cipherText}</e:CipherValue></e:CipherData></e:EncryptedData></s:Body>'

    # Create a body element for calculating the digest. MUST BE "expanded" so
    # that the cipher text is in decrypted form.
    xBody2 = f'<s:Body xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_2">{payload}</s:Body>'

    xTimeStamp = f'<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="uuid-{TSIdentifier}-2"><u:Created>{created}</u:Created><u:Expires>{expires}</u:Expires></u:Timestamp>'
    xAction = f'<a:Action xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_4" s:mustUnderstand="1">{action}</a:Action>'
    xMessageId = f'<a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_5">urn:uuid:{messageID}</a:MessageID>'
    xReplyTo = '<a:ReplyTo xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_6"><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>'
    xTo = f'<a:To xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="_7" s:mustUnderstand="1">http://{server}/adfs/services/policystoretransfer</a:To>'

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L865
    # Calculate digests and generate the SignedInfo
    digest_2 = base64.b64encode(get_digest(xBody2)).decode()
    digest_4 = base64.b64encode(get_digest(xAction)).decode()
    digest_5 = base64.b64encode(get_digest(xMessageId)).decode()
    digest_6 = base64.b64encode(get_digest(xReplyTo)).decode()
    digest_7 = base64.b64encode(get_digest(xTo)).decode()
    TSdigest = base64.b64encode(get_digest(xTimeStamp)).decode()
    signedInfo = f'<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></CanonicalizationMethod><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"></SignatureMethod><Reference URI="#_2"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{digest_2}</DigestValue></Reference><Reference URI="#_4"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{digest_4}</DigestValue></Reference><Reference URI="#_5"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{digest_5}</DigestValue></Reference><Reference URI="#_6"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{digest_6}</DigestValue></Reference><Reference URI="#_7"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{digest_7}</DigestValue></Reference><Reference URI="#uuid-{TSIdentifier}-2"><Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></DigestMethod><DigestValue>{TSdigest}</DigestValue></Reference></SignedInfo>'

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L874
    # Generate the signature by calculating HMACSHA1 of SignedInfo using the signing key
    signatureValue = base64.b64encode(
        hmac.new(
            signingKey,
            msg=signedInfo.encode(),
            digestmod=hashlib.sha1,
        ).digest()
    ).decode()

    # https://github.com/Gerenios/AADInternals/blob/master/ADFS_utils.ps1#L878
    # Generate Signature element and encrypt it using the encryption key
    xSignature = f'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">{signedInfo}<SignatureValue>{signatureValue}</SignatureValue><KeyInfo><o:SecurityTokenReference xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><o:Reference ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/dk" URI="#_0"/></o:SecurityTokenReference></KeyInfo></Signature>'
    encSignature = base64.b64encode(
        encrypt_wstrust_cipherdata(xSignature.encode(), encryptionKey)
    ).decode()

    envelope = f"""
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <s:Header>
            {xAction}
            {xMessageId}
            {xReplyTo}
            {xTo}
            <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                {xTimeStamp}
                <SecurityContextToken u:Id="{STSContext}" xmlns="http://schemas.xmlsoap.org/ws/2005/02/sc">
                    <Identifier>urn:uuid:{STIdentifier}</Identifier>
                </SecurityContextToken>
                <c:DerivedKeyToken u:Id="_0" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
                    <o:SecurityTokenReference>
                        <o:Reference URI="#{STSContext}"/>
                    </o:SecurityTokenReference>
                    <c:Offset>0</c:Offset>
                    <c:Length>24</c:Length>
                    <c:Nonce>{base64.b64encode(nonce0).decode()}</c:Nonce>
                </c:DerivedKeyToken>
                <c:DerivedKeyToken u:Id="_1" xmlns:c="http://schemas.xmlsoap.org/ws/2005/02/sc">
                    <o:SecurityTokenReference>
                        <o:Reference URI="#{STSContext}"/>
                    </o:SecurityTokenReference>
                    <c:Nonce>{base64.b64encode(nonce1).decode()}</c:Nonce>
                </c:DerivedKeyToken>
                <e:ReferenceList xmlns:e="http://www.w3.org/2001/04/xmlenc#">
                    <e:DataReference URI="#_3"/>
                    <e:DataReference URI="#_8"/>
                </e:ReferenceList>
                <e:EncryptedData Id="_8" Type="http://www.w3.org/2001/04/xmlenc#Element" xmlns:e="http://www.w3.org/2001/04/xmlenc#">
                    <e:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
                    <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                        <o:SecurityTokenReference>
                            <o:Reference ValueType="http://schemas.xmlsoap.org/ws/2005/02/sc/dk" URI="#_1"/>
                        </o:SecurityTokenReference>
                    </KeyInfo>
                    <e:CipherData>
                        <e:CipherValue>{encSignature}</e:CipherValue>
                    </e:CipherData>
                </e:EncryptedData>
            </o:Security>
        </s:Header>
        {xBody}
    </s:Envelope>
    """

    return envelope.rstrip()
