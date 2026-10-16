from __future__ import annotations

from collections import deque
from dataclasses import replace
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from mosh.models import CrawledPage, CrawlResult
from mosh.scope import ScopePolicy, normalize_url, strip_fragment


USER_AGENT = "mosh/0.1 discovery"


class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.references: list[str] = []
        self.forms: list[str] = []
        self.inline_scripts: list[str] = []
        self.title: str | None = None
        self._in_title = False
        self._title_parts: list[str] = []
        self._in_inline_script = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs if value}
        if tag == "title":
            self._in_title = True
        if tag == "a" and values.get("href"):
            self.links.append(self._absolute(values["href"]))
        elif tag == "form":
            action = values.get("action") or self.base_url
            self.forms.append(self._absolute(action))
        elif tag == "script":
            if values.get("src"):
                self.references.append(self._absolute(values["src"]))
            else:
                self._in_inline_script = True
                self._script_parts = []
        elif tag in {"img", "iframe", "source"} and values.get("src"):
            self.references.append(self._absolute(values["src"]))
        elif tag == "link" and values.get("href"):
            self.references.append(self._absolute(values["href"]))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
            title = "".join(self._title_parts).strip()
            self.title = title or None
        if tag == "script" and self._in_inline_script:
            self._in_inline_script = False
            script = "".join(self._script_parts).strip()
            if script:
                self.inline_scripts.append(script)
            self._script_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if self._in_inline_script:
            self._script_parts.append(data)

    def _absolute(self, value: str) -> str:
        return strip_fragment(urljoin(self.base_url, value))


class Crawler:
    def __init__(self, timeout: int = 10, *, request_headers: dict[str, str] | None = None, access_origin: str | None = None) -> None:
        self.timeout = timeout
        self.request_headers = request_headers or {}
        self.access_origin = _origin(access_origin) if access_origin else None

    def crawl(self, start_url: str, max_pages: int = 200, max_depth: int = 5) -> CrawlResult:
        normalized_start = normalize_url(start_url)
        scope = ScopePolicy.from_url(normalized_start)
        robots = self._fetch_robots(normalized_start)
        pages: list[CrawledPage] = []
        failed: list[dict[str, str | int]] = []
        out_of_scope: set[str] = set()
        seen: set[str] = set()
        queued: set[str] = {normalized_start}
        queue: deque[tuple[str, int]] = deque([(normalized_start, 0)])

        while queue and len(pages) < max_pages:
            url, depth = queue.popleft()
            queued.discard(url)
            if url in seen:
                continue
            seen.add(url)
            try:
                page = self._fetch_page(url)
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                failed.append({"url": url, "error": str(exc)})
                continue

            pages.append(page)
            if depth >= max_depth:
                continue

            discovered = [*page.links, *page.forms]
            for candidate in discovered:
                if not _is_http_url(candidate):
                    continue
                normalized = strip_fragment(candidate)
                if scope.in_scope(normalized):
                    if normalized not in seen and normalized not in queued and len(seen) + len(queued) < max_pages:
                        queue.append((normalized, depth + 1))
                        queued.add(normalized)
                else:
                    out_of_scope.add(normalized)

            for candidate in page.references:
                if _is_http_url(candidate) and not scope.in_scope(candidate):
                    out_of_scope.add(candidate)

        result = CrawlResult(
            start_url=normalized_start,
            pages=pages,
            out_of_scope=sorted(out_of_scope),
            failed=failed,
            robots=robots,
        )
        return _redact_crawl_result(result, self.request_headers)

    def _fetch_page(self, url: str) -> CrawledPage:
        response = self._open(url)
        final_url = strip_fragment(response.geturl() or url)
        status = response.status
        headers = dict(response.headers.items())
        content_type = response.headers.get("content-type", "")
        body = response.read()
        links: list[str] = []
        references: list[str] = []
        forms: list[str] = []
        inline_scripts: list[str] = []
        title: str | None = None

        if "html" in content_type.lower():
            text = body.decode(_charset_from_content_type(content_type), errors="replace")
            parser = LinkExtractor(final_url)
            parser.feed(text)
            links = sorted(set(parser.links))
            references = sorted(set(parser.references))
            forms = sorted(set(parser.forms))
            inline_scripts = parser.inline_scripts
            title = parser.title

        return CrawledPage(
            url=final_url,
            status=status,
            content_type=content_type,
            title=title,
            headers=headers,
            links=links,
            references=references,
            forms=forms,
            inline_scripts=inline_scripts,
        )

    def _fetch_robots(self, start_url: str) -> dict[str, object]:
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            response = self._open(robots_url)
            body = response.read().decode("utf-8", errors="replace")
        except (HTTPError, URLError, TimeoutError, ValueError):
            return {"url": robots_url, "found": False, "rules": [], "sitemaps": []}
        rules: list[dict[str, str]] = []
        sitemaps: list[str] = []
        for raw_line in body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            if key in {"allow", "disallow"}:
                rules.append({"directive": key, "path": value})
            elif key == "sitemap":
                sitemaps.append(value)
        return {"url": robots_url, "found": True, "rules": rules, "sitemaps": sitemaps}

    def _open(self, url: str):
        headers = {"User-Agent": USER_AGENT}
        if self.access_origin and _origin(url) == self.access_origin:
            headers.update(self.request_headers)
        request = Request(url, headers=headers)
        if self.request_headers:
            return build_opener(_SameOriginRedirects(self.access_origin)).open(request, timeout=self.timeout)
        return urlopen(request, timeout=self.timeout)


def _origin(url: str | None) -> tuple[str, str, int | None] | None:
    if not url:
        return None
    parsed = urlparse(url)
    try:
        return (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
    except ValueError:
        return None


def _redact_crawl_result(result: CrawlResult, headers: dict[str, str]) -> CrawlResult:
    secrets = [value for value in headers.values() if value]
    if not secrets:
        return result

    def redact(value):
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "[redacted]")
        elif isinstance(value, list):
            return [redact(item) for item in value]
        elif isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value

    return replace(
        result,
        start_url=redact(result.start_url),
        pages=[replace(page, **{key: redact(value) for key, value in page.to_dict().items()}) for page in result.pages],
        out_of_scope=redact(result.out_of_scope),
        failed=redact(result.failed),
        robots=redact(result.robots),
    )


class _SameOriginRedirects(HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int | None] | None) -> None:
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origin(newurl) != self.allowed_origin:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _is_http_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _charset_from_content_type(content_type: str) -> str:
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return part.split("=", 1)[1]
    return "utf-8"
