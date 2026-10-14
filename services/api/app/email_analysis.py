"""Bounded, offline parsing and explainable rules for manual email analysis."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from typing import Literal
from urllib.parse import urlsplit

EMAIL_RULESET_VERSION = "email-rules-v1"
MAX_EXTRACTED_URLS = 100
_URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)
_AUTH_RESULT_PATTERN = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|neutral|none|permerror|temperror)\b",
    re.IGNORECASE,
)
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"


@dataclass(frozen=True)
class EmailIndicator:
    """One explainable signal; it is not a verdict that the message is malicious."""

    rule_id: str
    description: str
    evidence: dict[str, str]
    severity: Literal["informational", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class EmailAnalysis:
    """Sanitized analysis output with no retained raw message content."""

    sender_domain: str | None
    return_path_domain: str | None
    reply_to_domain: str | None
    urls: list[dict[str, str | bool]]
    urls_truncated: bool
    ip_literal_hosts: list[str]
    authentication_results: list[dict[str, str]]
    indicators: list[EmailIndicator]
    parser_defects: list[str]


class InvalidEmailMessage(ValueError):
    """Raised when the submitted bytes cannot be treated as an email message."""


def _domain_from_address_header(value: str | None) -> str | None:
    if not value:
        return None
    address_match = re.search(r"<([^<>]+)>", value)
    address = address_match.group(1) if address_match else value.strip()
    if "@" not in address:
        return None
    domain = address.rsplit("@", maxsplit=1)[1].strip().rstrip(">")
    if len(domain) > 253:
        return None
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def _extract_message_text(message: Message) -> str:
    parts: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        if not isinstance(part, EmailMessage):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError) as exc:
            raise InvalidEmailMessage("Email body encoding is invalid.") from exc
        if isinstance(content, str):
            parts.append(content[:1_000_000])
    return "\n".join(parts)


def _extract_urls(text: str) -> tuple[list[dict[str, str | bool]], bool, list[str]]:
    extracted: dict[tuple[str, str], dict[str, str | bool]] = {}
    ip_literal_hosts: set[str] = set()
    urls_truncated = False
    for match in _URL_PATTERN.finditer(text):
        candidate = match.group(0).rstrip(_URL_TRAILING_PUNCTUATION)
        try:
            parsed = urlsplit(candidate)
            hostname = parsed.hostname
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not hostname
                or len(hostname) > 253
            ):
                continue
            host = hostname.encode("idna").decode("ascii").lower()
            try:
                ipaddress.ip_address(host)
                is_ip_literal = True
            except ValueError:
                is_ip_literal = False
        except (UnicodeError, ValueError):
            continue
        if is_ip_literal:
            if host not in ip_literal_hosts and len(ip_literal_hosts) < MAX_EXTRACTED_URLS:
                ip_literal_hosts.add(host)
        key = (parsed.scheme.lower(), host)
        if key not in extracted and len(extracted) >= MAX_EXTRACTED_URLS:
            urls_truncated = True
            continue
        extracted[key] = {
            "scheme": parsed.scheme.lower(),
            "host": host,
            "is_ip_literal": is_ip_literal,
        }
    return list(extracted.values()), urls_truncated, sorted(ip_literal_hosts)[:MAX_EXTRACTED_URLS]


def analyze_email(raw_message: bytes) -> EmailAnalysis:
    """Parse and analyze an email entirely offline; caller must enforce byte limits."""

    if not raw_message:
        raise InvalidEmailMessage("Email message is empty.")

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        if not message.keys():
            raise InvalidEmailMessage("Email message has no valid headers.")

        parser_defects = sorted(
            {type(defect).__name__ for part in message.walk() for defect in part.defects}
        )
        if parser_defects:
            raise InvalidEmailMessage("Email message has malformed structure.")

        sender_domain = _domain_from_address_header(message.get("From"))
        return_path_domain = _domain_from_address_header(message.get("Return-Path"))
        reply_to_domain = _domain_from_address_header(message.get("Reply-To"))

        authentication_results: list[dict[str, str]] = []
        for header in message.get_all("Authentication-Results", []):
            authentication_results.extend(
                {"mechanism": match.group(1).lower(), "result": match.group(2).lower()}
                for match in _AUTH_RESULT_PATTERN.finditer(str(header))
            )

        text = _extract_message_text(message)
        urls, urls_truncated, ip_literal_hosts = _extract_urls(text)
    except InvalidEmailMessage:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidEmailMessage("Email message could not be parsed safely.") from exc

    indicators: list[EmailIndicator] = []

    failed_authentication = [
        result
        for result in authentication_results
        if result["result"] in {"fail", "softfail", "permerror"}
    ]
    if failed_authentication:
        indicators.append(
            EmailIndicator(
                rule_id="email.authentication-failure",
                description=(
                    "The uploaded message claims one or more sender-authentication checks "
                    "did not pass; these headers are unverified."
                ),
                evidence={
                    "results": ",".join(
                        f"{result['mechanism']}={result['result']}"
                        for result in failed_authentication
                    ),
                    "source": "unverified_message_header",
                },
                severity="medium",
            )
        )

    if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        indicators.append(
            EmailIndicator(
                rule_id="email.reply-to-domain-mismatch",
                description="The Reply-To domain differs from the From domain.",
                evidence={
                    "sender_domain": sender_domain,
                    "reply_to_domain": reply_to_domain,
                },
                severity="medium",
            )
        )

    if ip_literal_hosts:
        indicators.append(
            EmailIndicator(
                rule_id="email.ip-literal-link",
                description="A message link uses an IP address instead of a domain name.",
                evidence={"hosts": ",".join(ip_literal_hosts)},
                severity="medium",
            )
        )

    return EmailAnalysis(
        sender_domain=sender_domain,
        return_path_domain=return_path_domain,
        reply_to_domain=reply_to_domain,
        urls=urls,
        urls_truncated=urls_truncated,
        ip_literal_hosts=ip_literal_hosts,
        authentication_results=authentication_results,
        indicators=indicators,
        parser_defects=parser_defects,
    )
