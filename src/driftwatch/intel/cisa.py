"""Fetch and parse CISA cybersecurity advisories.

CISA joint advisories (``AA24-…``) list the ATT&CK techniques they observed, usually in tables and inline
references like "T1059.001". This module reads the public advisories RSS feed, downloads an advisory
page, strips it to text and extracts every technique id together with the sentence it appeared in. That
gives the drafter a precise, deterministic technique list before any LLM is involved.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, ClassVar

import httpx
from defusedxml import ElementTree as SafeET

FEED_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
ADVISORY_ID = re.compile(r"\b(AA\d{2}-\d{3}[A-Z])\b", re.IGNORECASE)
TECHNIQUE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
MAX_TEXT = 40_000
USER_AGENT = "Driftwatch/1.0 (+https://github.com/; continuous security validation lab)"


class IntelError(Exception):
    """Raised when a feed or advisory cannot be fetched or parsed."""


@dataclass
class TechniqueMention:
    id: str
    context: str


@dataclass
class Advisory:
    id: str | None
    title: str
    url: str
    published: str | None = None
    techniques: list[TechniqueMention] = field(default_factory=list)
    text: str = ""

    @property
    def technique_ids(self) -> list[str]:
        return [t.id for t in self.techniques]

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "url": self.url, "published": self.published,
                "techniques": [t.__dict__ for t in self.techniques], "text_chars": len(self.text)}


class _TextExtractor(HTMLParser):
    """HTML to text, dropping script and style, keeping block boundaries as newlines."""

    BLOCKS: ClassVar[set[str]] = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table",
                                  "section", "article"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag in self.BLOCKS:
            self.parts.append("\n")
        elif tag in ("td", "th"):
            self.parts.append(" | ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip = max(0, self._skip - 1)
        elif tag == "title":
            self._in_title = False
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._in_title:
            self.title += data
        self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    """Return (title, text)."""
    parser = _TextExtractor()
    parser.feed(html)
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    text = re.sub(r"\n\s*\n+", "\n", text).strip()
    return parser.title.strip(), text


def parse_advisory(html: str, url: str, published: str | None = None) -> Advisory:
    """Extract id, title, techniques (with context) and text from an advisory page."""
    title, text = html_to_text(html)
    m = ADVISORY_ID.search(url) or ADVISORY_ID.search(title) or ADVISORY_ID.search(text)
    mentions: dict[str, TechniqueMention] = {}
    for line in text.splitlines():
        for tid in TECHNIQUE.findall(line):
            if tid not in mentions:
                mentions[tid] = TechniqueMention(tid, line.strip()[:300])
    return Advisory(
        id=m.group(1).upper() if m else None,
        title=title.split("|")[0].strip() or url,
        url=url,
        published=published,
        techniques=sorted(mentions.values(), key=lambda t: t.id),
        text=text[:MAX_TEXT],
    )


def parse_feed(xml_text: str) -> list[dict[str, str | None]]:
    """Items of an RSS 2.0 feed: title, link, published."""
    try:
        root = SafeET.fromstring(xml_text)
    except SafeET.ParseError as exc:
        raise IntelError(f"invalid feed XML: {exc}") from exc
    items = []
    for item in root.iter("item"):
        items.append({
            "title": (item.findtext("title") or "").strip(),
            "link": (item.findtext("link") or "").strip(),
            "published": (item.findtext("pubDate") or "").strip() or None,
        })
    return items


class CisaClient:
    """HTTP access to the CISA feed and advisory pages."""

    def __init__(self, transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> None:
        self._http = httpx.Client(timeout=timeout, follow_redirects=True, transport=transport,
                                  headers={"User-Agent": USER_AGENT})

    def close(self) -> None:
        self._http.close()

    def _get(self, url: str) -> str:
        if not url.startswith("https://"):
            raise IntelError("only https URLs are fetched")
        try:
            resp = self._http.get(url)
        except httpx.HTTPError as exc:
            raise IntelError(f"cannot fetch {url}: {exc}") from exc
        if resp.status_code >= 400:
            raise IntelError(f"{url} returned {resp.status_code}")
        return resp.text

    def latest(self, feed_url: str = FEED_URL, limit: int = 10) -> list[dict[str, str | None]]:
        return parse_feed(self._get(feed_url))[:limit]

    def advisory(self, url: str, published: str | None = None) -> Advisory:
        return parse_advisory(self._get(url), url, published)
