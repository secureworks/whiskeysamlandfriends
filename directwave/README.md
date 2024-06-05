# Shock N' Awe

This is a proof of concept tool to execute commands on all of the Virtual Machines within a given tenant similarly to ShockNAwe.py, except instead of relying on a Golden SAML attack chain to obtain an Access Token, the Access Token is supplied using the `--access-token` argument switch.

## PoC Demo

Similar functionality to ShockNAwe, but without the Golden SAML attack chain.

![ShockNAwe](resc/shocknawe-demo.mp4)

## Usage

```
usage: directwave.py [-h] --command COMMAND --access-token ACCESS_TOKEN [--rate RATE]
                          [--debug]

Shock N' Awe: Deploy a Payload to an Azure Subscription | v0.1.0

optional arguments:
  -h, --help            show this help message and exit


  --access-token        Global Administrator's Access Token for Azure Core Management..

  --rate RATE           Number of threads to run concurrently. Default: 5


  --command COMMAND     Command to be run on the victim system(s)


  --debug               Enable debugging
```

> The current implementation targets Windows hosts for command execution via Powershell
