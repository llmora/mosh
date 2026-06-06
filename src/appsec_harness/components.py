from __future__ import annotations

import re
from urllib.parse import urlparse

from appsec_harness.models import CrawlResult


LIBRARY_PATTERNS = {
    "jquery": re.compile(r"jquery[-.]?([0-9][^/._-]*)?", re.IGNORECASE),
    "react": re.compile(r"react(?:\.production|\.development)?(?:[-.]?([0-9][^/._-]*))?", re.IGNORECASE),
    "vue": re.compile(r"vue(?:\.min)?(?:[-.]?([0-9][^/._-]*))?", re.IGNORECASE),
    "angular": re.compile(r"angular(?:[-.]?([0-9][^/._-]*))?", re.IGNORECASE),
    "bootstrap": re.compile(r"bootstrap(?:[-.]?([0-9][^/._-]*))?", re.IGNORECASE),
    "lodash": re.compile(r"lodash(?:[-.]?([0-9][^/._-]*))?", re.IGNORECASE),
}


def compile_component_inventory(crawl: CrawlResult) -> list[dict[str, str]]:
    components: dict[tuple[str, str, str], dict[str, str]] = {}

    def add(component_type: str, name: str, version: str, source: str, evidence: str) -> None:
        key = (component_type, name.lower(), version)
        components.setdefault(
            key,
            {
                "type": component_type,
                "name": name,
                "version": version,
                "source": source,
                "evidence": evidence,
            },
        )

    for page in crawl.pages:
        for header, value in page.headers.items():
            header_l = header.lower()
            if header_l == "server":
                add("server", value, "unknown", page.url, "Server header")
            elif header_l == "x-powered-by":
                add("framework", value, "unknown", page.url, "X-Powered-By header")
            elif header_l == "via":
                add("proxy", value, "unknown", page.url, "Via header")

        for reference in page.references:
            path = urlparse(reference).path
            if path.endswith(".js"):
                add("asset", path.rsplit("/", 1)[-1], "unknown", reference, "JavaScript reference")
            elif path.endswith(".css"):
                add("asset", path.rsplit("/", 1)[-1], "unknown", reference, "Stylesheet reference")
            for library, pattern in LIBRARY_PATTERNS.items():
                match = pattern.search(reference)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else "unknown"
                    add("library", library, version, reference, "Matched referenced asset name")

    return sorted(components.values(), key=lambda item: (item["type"], item["name"], item["source"]))
