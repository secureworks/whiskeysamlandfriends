# Tickets, Please

TicketsPlease is a ticket/token generation tool suite.

# Table of Contents

<!--ts-->
   * [Environment Setup](#environment-setup)
   * [Modules](#modules)
      * [ldap](docs/LDAP.md)
      * [dcsync](docs/DCSYNC.md)
      * [ticket](docs/TICKET.md)
         * [How It Works](docs/TICKET.md#how-it-works)
         * [Usage](docs/TICKET.md#usage)
      * [adfs](docs/ADFS.md)
         * [How It Works](docs/ADFS.md#how-it-works)
         * [Usage](docs/ADFS.md#usage)
      * [saml](docs/SAML.md)
         * [How It Works](docs/SAML.md#how-it-works)
         * [Usage](docs/SAML.md#usage)
      * [azure](docs/AZURE.md)
         * [How It Works](docs/AZURE.md#how-it-works)
         * [Usage](docs/AZURE.md#usage)

<br>

<hr style="border:2px solid gray"> </hr>

<br>

# Environment Setup

| Step | Instructions | Command |
|---   | ---          | ---     |
| 1 | Install the required libraries on the server | `apt install libssl-dev wmi-client` |
| 2 | Install the Python virtual environment module | `pip3 install virtualenv` |
| 3 | Set up a Python virtual environment | `virtualenv venv` |
| 4 | Activate the Python Virtual environment | `source venv/bin/activate` |
| 5a | Install as a Python package | `pip3 install .` |
| 5b | Install Python requirements to run independently | `pip3 install -r requirements.txt` |

# Modules

> This tool leverages two public projects not via pip: [FireEye's ADFSpoof](https://github.com/fireeye/ADFSpoof) and the [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) script from Impacket.
>
> The `ticket` and `adfs` modules are based on the blog post via [o365blog](https://o365blog.com/post/adfs/#remote) and the [Export-ADFSConfiguration](https://github.com/Gerenios/AADInternals/blob/c255cd66a3731c32cfbdf9fdb17f2b03c7665b72/ADFS.ps1#L133) function via AADInternals.

```
usage: ticketsplease [-h] {ldap,dcsync,ticket,adfs,saml,azure} ...

Tickets, Please: Ticket/Token Generator | v0.1.0

positional arguments:
  {ldap,dcsync,ticket,adfs,saml,azure}
                        Ticket/Token Generation Modules

optional arguments:
  -h, --help            show this help message and exit
```

See the individual module [docs](docs/) via the [Table of Contents](#table-of-contents).
