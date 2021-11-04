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

import html
import logging
import wmi_client_wrapper as wmi  # type: ignore


class WMIC:
    @classmethod
    def get_service_user(
        cls,
        domain: str,
        host: str,
        user: str,
        password: str,
        service: str = "adfssrv",
    ) -> str:
        """Using WMIC, retrieve username for a given service account.
        Default to looking for the AD FS Service account.

        Arguments:
            domain: target domain
            host: target server to query
            user: authenticating user
            password: password of authenticating user
            service: name of service to query for

        Returns:
            the target service username
        """
        # Convert the authenticating user and domain to the appropriate
        # format
        domain_user = f"{domain}\\{user}"

        # Escape the raw password (there is no PtH options for WMIC)
        escaped_password = html.escape(password)
        connection = wmi.WmiClientWrapper(
            username=domain_user,
            password=escaped_password,
            host=host,
        )

        query = f'SELECT * FROM Win32_Service Where Name = "{service}"'
        output = connection.query(query)[0]

        if "StartName" not in output.keys():
            raise ValueError(f"could not retrieve username for: {service}")

        service_user = output["StartName"].split("\\")[1]
        logging.info(f"[ * ] Service account for {service}: {service_user}")

        return service_user
