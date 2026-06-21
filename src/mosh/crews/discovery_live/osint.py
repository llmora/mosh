from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen


OSINT_USER_AGENT = "mosh/0.1 passive-osint"


@dataclass(frozen=True)
class OsintObservation:
    host: str
    source_tool: str
    evidence: list[str] = field(default_factory=list)
    confidence: str = "observed"
    port: int | None = None
    protocol: str | None = None


class ExternalOsintProvider(Protocol):
    name: str

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        pass


class CrtShOsintProvider:
    name = "crtsh_external_osint"

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        query_url = "https://crt.sh/?" + urlencode({"q": f"%.{root_domain}", "output": "json"})
        payload = _open_json(Request(query_url, headers={"User-Agent": OSINT_USER_AGENT}), timeout)
        if not isinstance(payload, list):
            raise ValueError("crt.sh returned non-list JSON")
        observations: list[OsintObservation] = []
        seen: set[str] = set()
        for item in payload:
            if not isinstance(item, dict):
                continue
            name_value = item.get("name_value")
            if not isinstance(name_value, str):
                continue
            for raw_host in name_value.splitlines():
                host = normalize_osint_host(raw_host)
                if not host or host in seen:
                    continue
                seen.add(host)
                observations.append(
                    OsintObservation(
                        host=host,
                        source_tool=self.name,
                        evidence=["crt.sh certificate transparency name_value"],
                    )
                )
        return observations


class SecurityTrailsOsintProvider:
    name = "securitytrails_external_osint"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        query_url = f"https://api.securitytrails.com/v1/domain/{root_domain}/subdomains"
        payload = _open_json(
            Request(
                query_url,
                headers={
                    "APIKEY": self.api_key,
                    "Accept": "application/json",
                    "User-Agent": OSINT_USER_AGENT,
                },
            ),
            timeout,
        )
        subdomains = payload.get("subdomains") if isinstance(payload, dict) else None
        if not isinstance(subdomains, list):
            raise ValueError("SecurityTrails returned no subdomains list")
        observations: list[OsintObservation] = []
        for subdomain in subdomains:
            if not isinstance(subdomain, str):
                continue
            host = normalize_osint_host(f"{subdomain}.{root_domain}" if subdomain else root_domain)
            if host:
                observations.append(
                    OsintObservation(
                        host=host,
                        source_tool=self.name,
                        evidence=["SecurityTrails subdomains response"],
                    )
                )
        return observations


class ShodanOsintProvider:
    name = "shodan_external_osint"

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        query_url = "https://api.shodan.io/shodan/host/search?" + urlencode(
            {"query": f"hostname:{root_domain}", "key": self.api_key}
        )
        payload = _open_json(Request(query_url, headers={"User-Agent": OSINT_USER_AGENT}), timeout)
        matches = payload.get("matches") if isinstance(payload, dict) else None
        if not isinstance(matches, list):
            raise ValueError("Shodan returned no matches list")
        observations: list[OsintObservation] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            port = _int_or_none(match.get("port"))
            protocol = _protocol_from_service(match.get("ssl"), match.get("_shodan"), port)
            for host in _string_list(match.get("hostnames")):
                normalized = normalize_osint_host(host)
                if not normalized:
                    continue
                observations.append(
                    OsintObservation(
                        host=normalized,
                        source_tool=self.name,
                        evidence=["Shodan hostname search result"],
                        port=port,
                        protocol=protocol,
                    )
                )
        return observations


class CensysOsintProvider:
    name = "censys_external_osint"

    def __init__(self, api_id: str, api_secret: str) -> None:
        self.api_id = api_id
        self.api_secret = api_secret

    def query(self, root_domain: str, timeout: int) -> list[OsintObservation]:
        query = f"dns.names: *.{root_domain} or services.tls.certificates.leaf_data.names: *.{root_domain}"
        query_url = "https://search.censys.io/api/v2/hosts/search?" + urlencode(
            {"q": query, "per_page": 50, "virtual_hosts": "EXCLUDE"}
        )
        auth = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode("utf-8")).decode("ascii")
        payload = _open_json(
            Request(
                query_url,
                headers={
                    "Authorization": f"Basic {auth}",
                    "Accept": "application/json",
                    "User-Agent": OSINT_USER_AGENT,
                },
            ),
            timeout,
        )
        result = payload.get("result") if isinstance(payload, dict) else None
        hits = result.get("hits") if isinstance(result, dict) else None
        if not isinstance(hits, list):
            raise ValueError("Censys returned no hits list")
        observations: list[OsintObservation] = []
        for hit in hits:
            if not isinstance(hit, dict):
                continue
            observations.extend(_censys_hit_observations(hit, self.name))
        return observations


def build_default_osint_providers(
    *,
    shodan_api_key: str | None = None,
    securitytrails_api_key: str | None = None,
    censys_api_id: str | None = None,
    censys_api_secret: str | None = None,
) -> list[ExternalOsintProvider]:
    providers: list[ExternalOsintProvider] = [CrtShOsintProvider()]
    if securitytrails_api_key:
        providers.append(SecurityTrailsOsintProvider(securitytrails_api_key))
    if shodan_api_key:
        providers.append(ShodanOsintProvider(shodan_api_key))
    if censys_api_id and censys_api_secret:
        providers.append(CensysOsintProvider(censys_api_id, censys_api_secret))
    return providers


def normalize_osint_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or any(character.isspace() for character in host):
        return ""
    if "/" in host or ":" in host:
        return ""
    return host


def _open_json(request: Request, timeout: int) -> Any:
    with urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
    return json.loads(body or "null")


def _censys_hit_observations(hit: dict[str, Any], source_tool: str) -> list[OsintObservation]:
    observations: list[OsintObservation] = []
    top_level_hosts = [hit.get("name"), *_string_list(hit.get("names")), *_string_list(hit.get("dns_names"))]
    for host in top_level_hosts:
        if not isinstance(host, str):
            continue
        normalized = normalize_osint_host(host)
        if normalized:
            observations.append(
                OsintObservation(
                    host=normalized,
                    source_tool=source_tool,
                    evidence=["Censys host search result"],
                )
            )
    services = hit.get("services")
    if not isinstance(services, list):
        return observations
    for service in services:
        if not isinstance(service, dict):
            continue
        port = _int_or_none(service.get("port"))
        protocol = _protocol_from_service(None, service.get("extended_service_name") or service.get("service_name"), port)
        for host in _censys_service_hosts(service):
            normalized = normalize_osint_host(host)
            if not normalized:
                continue
            observations.append(
                OsintObservation(
                    host=normalized,
                    source_tool=source_tool,
                    evidence=["Censys service certificate or DNS result"],
                    port=port,
                    protocol=protocol,
                )
            )
    return observations


def _censys_service_hosts(service: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    tls = service.get("tls")
    if isinstance(tls, dict):
        certificates = tls.get("certificates")
        if isinstance(certificates, dict):
            leaf = certificates.get("leaf_data")
            if isinstance(leaf, dict):
                hosts.extend(_string_list(leaf.get("names")))
    hosts.extend(_string_list(service.get("dns_names")))
    return hosts


def _protocol_from_service(ssl_value: Any, service_value: Any, port: int | None) -> str | None:
    service = _service_text(service_value)
    if ssl_value or "https" in service or "tls" in service:
        return "https"
    if "http" in service:
        return "http"
    if port in {443, 8443, 9443}:
        return "https"
    if port in {80, 3000, 5000, 8000, 8080, 9000}:
        return "http"
    return None


def _service_text(value: Any) -> str:
    if isinstance(value, dict):
        parts = [item for item in (value.get("module"), value.get("name"), value.get("id")) if isinstance(item, str)]
        return " ".join(parts).lower()
    return str(value or "").lower()


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, str):
        return [value]
    return []
