from __future__ import annotations
import json
from urllib.parse import urljoin, urlparse

from mosh.models import CrawledPage


def parse_openapi_spec(spec_url: str, spec_json: str) -> list[CrawledPage]:
    """Parse an OpenAPI/Swagger JSON spec and return CrawledPage entries for each path."""
    try:
        spec = json.loads(spec_json)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(spec, dict):
        return []
    if 'swagger' not in spec and 'openapi' not in spec:
        return []
    paths = spec.get('paths', {})
    if not isinstance(paths, dict):
        return []
    # Extract base URL from spec or derive from spec_url
    base_url = _extract_base_url(spec, spec_url)
    pages: list[CrawledPage] = []
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, details in methods.items():
            if method.upper() not in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                continue
            endpoint_url = base_url.rstrip('/') + '/' + path.lstrip('/')
            description = ''
            if isinstance(details, dict):
                description = details.get('description', '') or details.get('summary', '') or ''
            pages.append(CrawledPage(
                url=endpoint_url,
                status=0,
                content_type='',
                title=f"{method.upper()} {path}",
                headers={},
                links=[],
                references=[spec_url],
                forms=[],
                inline_scripts=[],
            ))
    return pages


def is_openapi_spec(content_type: str, body: str) -> bool:
    """Check if a response looks like an OpenAPI/Swagger spec."""
    if 'json' not in content_type.lower():
        return False
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(data, dict):
        return False
    return ('swagger' in data or 'openapi' in data) and 'paths' in data


def _extract_base_url(spec: dict, spec_url: str) -> str:
    """Extract base URL from spec or derive from spec_url."""
    # OpenAPI 3.x
    servers = spec.get('servers', [])
    if isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict) and first.get('url'):
            url = str(first['url']).strip()
            if url.startswith(('http://', 'https://')):
                return url
            if url:
                return urljoin(spec_url, url)
    # Swagger 2.x
    host = spec.get('host', '')
    if host:
        scheme = 'https'
        schemes = spec.get('schemes', [])
        if isinstance(schemes, list) and schemes:
            scheme = schemes[0]
        base_path = spec.get('basePath', '')
        return f"{scheme}://{host}{base_path}"
    # Fallback: derive from spec URL
    parsed = urlparse(spec_url)
    return f"{parsed.scheme}://{parsed.netloc}"
