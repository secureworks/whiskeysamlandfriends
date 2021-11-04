# Shock N' Awe

This is a proof of concept tool to generate a Golden SAML token that will be used to request an Access Token from Azure Core Management which will then be used to enumerate and attack the virtual machines within the Azure subscription.

## PoC Demo

![ShockNAwe](resc/shocknawe-demo.mp4)

## Usage

```
usage: shocknawe.py [-h] --target-user TARGET_USER --domain DOMAIN --adfs-host ADFS_HOST
                    --dc-ip DC_IP --domain-username DOMAIN_USERNAME
                    --domain-password DOMAIN_PASSWORD [--rate RATE] [--debug]

Shock N' Awe: Deploy a Payload to an Azure Subscription | v0.1.0

optional arguments:
  -h, --help            show this help message and exit

  --target-user TARGET_USER
                        Target Cloud User username

  --domain DOMAIN       Target Domain

  --adfs-host ADFS_HOST
                        Target ADFS Server

  --dc-ip DC_IP         Target Domain Controller

  --domain-username DOMAIN_USERNAME
                        Domain Username for DCSync

  --domain-password DOMAIN_PASSWORD
                        Password for Domain Username

  --rate RATE           Number of threads to run concurrently.
                        Default: 5

  --malicious-host MALICIOUS_HOST
                        IP address/domain name of the malicious server hosting payloads

  --payload-name PAYLOAD_NAME
                        Name of remote payload file

  --command COMMAND     Command to be run on the victim system(s)

  --debug               Enable debugging
```

> The current implementation targets Windows hosts for command execution via Powershell