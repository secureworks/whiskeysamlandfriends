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

from xml.etree import ElementTree
from ticketsplease.modules.azure.defs import NAMESPACES


def parse_golden_saml(token: str) -> str:
    """Extract the assertion from a full Golden SAML XML object"""
    for k, v in NAMESPACES.items():
        ElementTree.register_namespace(k, v[k])

    tree = ElementTree.fromstring(token)
    saml_assertion = tree.find(".//saml:Assertion", NAMESPACES["saml"])
    saml = ElementTree.tostring(
        saml_assertion,
        xml_declaration=False,
        encoding="utf-8",
        method="xml",
    )
    return saml
