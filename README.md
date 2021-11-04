# WhiskeySAML and Friends

## TicketsPlease

[TicketsPlease](ticketsplease/): Python library to assist with the generation of Kerberos tickets, remote retrieval of ADFS configuration settings, generation of Golden SAML tokens, and retrieval of Azure Access Tokens.

## WhiskeySAML

[WhiskeySAML](whiskeysaml/): Proof of concept tool for a Golden SAML attack with Remote ADFS Configuration Extraction. This tool leverages the TicketsPlease library.

## ShockNAwe

[ShockNAwe](shocknawe/): Proof of concept tool to generate a Golden SAML token that will be used to request an Access Token from Azure Core Management which will then be used to enumerate and attack the virtual machines within the Azure subscription.
