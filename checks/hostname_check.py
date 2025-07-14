import re

from infrahub_sdk.checks import InfrahubCheck


class HostnameCheck(InfrahubCheck):
    query = "hostname_check"

    def _regex_check(self, site: str, role: str) -> re.Pattern:
        return re.compile(rf"^{re.escape(site)}-{re.escape(role)}-[0-9]{{3}}$")

    def validate(self, data: dict) -> None:
        for edge in data["NetworkDevice"]["edges"]:
            device = edge["node"]
            site = device["site"]["value"]
            role = device["role"]["value"]
            hostname = device["hostname"]["value"]

            if not self._regex_check(site, role).match(hostname):
                self.log_error(message=f"Invalid hostname '{hostname}'. Expected format: '{site}-{role}-###' where ### is a 3-digit number.")
