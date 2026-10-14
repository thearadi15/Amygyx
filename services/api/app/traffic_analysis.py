"""Bounded, offline analysis of unidirectional IP flow CSV files."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass
from typing import Literal

TRAFFIC_RULESET_VERSION = "unidirectional-ip-rules-v1"
MAX_FLOW_ROWS = 10_000
MAX_FLOW_SOURCES = 5_000
PORT_SCAN_THRESHOLD = 20
DESTINATION_FANOUT_THRESHOLD = 50
REQUIRED_COLUMNS = {
    "source_ip",
    "destination_ip",
    "destination_port",
    "protocol",
    "bytes",
    "packets",
}
_PROTOCOL_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,16}$")


@dataclass(frozen=True)
class TrafficIndicator:
    """One explainable traffic pattern requiring analyst review."""

    rule_id: str
    description: str
    severity: Literal["low", "medium", "high"]
    evidence: dict[str, str | int]


@dataclass(frozen=True)
class TrafficAnalysis:
    """Aggregate-only output; raw flow records are not retained."""

    rows_processed: int
    indicators: list[TrafficIndicator]


class InvalidTrafficData(ValueError):
    """Raised when uploaded flow data violates the supported CSV contract."""


@dataclass
class _SourceFlows:
    protocol: str
    destination_ports: set[int]
    destination_ips: set[str]
    flow_count: int = 0


def _parse_ip(value: str, column: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InvalidTrafficData(f"Invalid IP address in {column}.") from exc


def analyze_unidirectional_flows(raw_csv: bytes) -> TrafficAnalysis:
    """Analyze a CSV of one-way flow records without retaining individual records."""

    if not raw_csv:
        raise InvalidTrafficData("Flow CSV is empty.")
    try:
        text = raw_csv.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidTrafficData("Flow CSV must use UTF-8 encoding.") from exc

    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if reader.fieldnames is None:
            raise InvalidTrafficData("Flow CSV must include a header row.")
        reader.fieldnames = [header.strip() for header in reader.fieldnames if header]
        headers = set(reader.fieldnames)
        if len(headers) != len(reader.fieldnames):
            raise InvalidTrafficData("Flow CSV contains duplicate column names.")
        missing_headers = REQUIRED_COLUMNS - headers
        if missing_headers:
            missing = ", ".join(sorted(missing_headers))
            raise InvalidTrafficData(f"Flow CSV is missing required columns: {missing}.")

        source_flows: dict[tuple[str, str], _SourceFlows] = {}
        rows_processed = 0
        for row in reader:
            if None in row or any(row.get(column) is None for column in REQUIRED_COLUMNS):
                raise InvalidTrafficData("Flow CSV contains a row with missing columns.")
            rows_processed += 1
            if rows_processed > MAX_FLOW_ROWS:
                raise InvalidTrafficData(f"Flow CSV exceeds the {MAX_FLOW_ROWS:,}-row limit.")

            source_ip = _parse_ip(row["source_ip"] or "", "source_ip")
            destination_ip = _parse_ip(row["destination_ip"] or "", "destination_ip")
            try:
                destination_port = int(row["destination_port"] or "")
                byte_count = int(row["bytes"] or "")
                packet_count = int(row["packets"] or "")
            except ValueError as exc:
                raise InvalidTrafficData("Flow CSV contains a non-integer numeric field.") from exc
            if not 1 <= destination_port <= 65535:
                raise InvalidTrafficData("destination_port must be between 1 and 65535.")
            if byte_count < 0 or packet_count < 0:
                raise InvalidTrafficData("bytes and packets must be non-negative.")
            protocol = (row["protocol"] or "").strip()
            if not _PROTOCOL_PATTERN.fullmatch(protocol):
                raise InvalidTrafficData("Flow CSV contains an invalid protocol value.")

            normalized_protocol = protocol.lower()
            source_key = (source_ip, normalized_protocol)
            flows = source_flows.get(source_key)
            if flows is None:
                if len(source_flows) >= MAX_FLOW_SOURCES:
                    raise InvalidTrafficData(
                        f"Flow CSV exceeds the {MAX_FLOW_SOURCES:,}-source limit."
                    )
                flows = _SourceFlows(
                    protocol=normalized_protocol,
                    destination_ports=set(),
                    destination_ips=set(),
                )
                source_flows[source_key] = flows
            flows.destination_ports.add(destination_port)
            flows.destination_ips.add(destination_ip)
            flows.flow_count += 1
    except csv.Error as exc:
        raise InvalidTrafficData("Flow CSV has malformed quoting or row structure.") from exc

    indicators: list[TrafficIndicator] = []
    if rows_processed == 0:
        raise InvalidTrafficData("Flow CSV must contain at least one flow record.")

    for (source_ip, protocol), flows in sorted(source_flows.items()):
        if len(flows.destination_ports) >= PORT_SCAN_THRESHOLD:
            indicators.append(
                TrafficIndicator(
                    rule_id="network.unidirectional-port-scan",
                    description=(
                        "One source contacted many distinct destination ports in one-way flow "
                        "records; this may indicate scanning or authorized discovery."
                    ),
                    severity="medium",
                    evidence={
                        "source_ip": source_ip,
                        "protocol": protocol,
                        "distinct_destination_ports": len(flows.destination_ports),
                        "flow_count": flows.flow_count,
                        "threshold": PORT_SCAN_THRESHOLD,
                    },
                )
            )
        if len(flows.destination_ips) >= DESTINATION_FANOUT_THRESHOLD:
            indicators.append(
                TrafficIndicator(
                    rule_id="network.unidirectional-destination-fanout",
                    description=(
                        "One source contacted many distinct destination IPs; this may indicate "
                        "broad discovery or expected service activity."
                    ),
                    severity="medium",
                    evidence={
                        "source_ip": source_ip,
                        "protocol": protocol,
                        "distinct_destination_ips": len(flows.destination_ips),
                        "flow_count": flows.flow_count,
                        "threshold": DESTINATION_FANOUT_THRESHOLD,
                    },
                )
            )

    return TrafficAnalysis(rows_processed=rows_processed, indicators=indicators)
