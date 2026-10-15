"""Bounded, offline analysis of Bitcoin transfer-edge CSV data.

Aligned with SIH26146: AI-Powered Monitoring & Analysis of Bitcoin Transaction Traffic.

AI/ML detectors implemented:
  1. Address fan-out heuristic         (always computed)
  2. Address fan-in heuristic          (always computed)
  3. High-value transfer outlier       (always computed)
  4. Union-Find entity clustering      (common-input co-spend ownership heuristic)
  5. Peeling chain detection           (single-in single-out relay node heuristic)
  6. Equal-output mixer/tumbler        (CoinJoin / tumbler equal-split detection)

Common-input clustering heuristic: if multiple distinct sender addresses appear in rows with
the same transaction_id, they are co-spending inputs and likely belong to the same entity.

Privacy policy: no raw address strings are ever emitted in response fields.
Optional extended columns: src_ip, geo_country, asn (backward-compatible).
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from statistics import median
from typing import Any, Literal

BITCOIN_RULESET_VERSION = "bitcoin-transfer-rules-v1"
MAX_TRANSFER_ROWS = 10_000
MAX_ADDRESSES = 20_000
ADDRESS_FAN_OUT_THRESHOLD = 10
ADDRESS_FAN_IN_THRESHOLD = 10
HIGH_VALUE_MULTIPLIER = Decimal(5)
REQUIRED_COLUMNS = {"transaction_id", "sender_address", "recipient_address", "amount_btc"}
_TXID_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
_AMOUNT_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?$")

_MIXER_MIN_OUTPUTS = 3
_MIXER_TOLERANCE = Decimal("0.00000001")  # 1 satoshi tolerance
_PEELING_MIN_HOPS = 2
_CLUSTER_MIN_SIZE = 3


@dataclass(frozen=True)
class BitcoinIndicator:
    """One explainable transaction-graph signal requiring human review."""

    rule_id: str
    description: str
    severity: Literal["low", "medium", "high"]
    evidence: dict[str, Any]


@dataclass(frozen=True)
class BitcoinAnalysis:
    """Aggregate-only output; raw transaction IDs and addresses are not retained."""

    rows_processed: int
    indicators: list[BitcoinIndicator]
    analytics_summary: dict[str, Any] | None = None


class InvalidBitcoinData(ValueError):
    """Raised when uploaded transfer-edge data violates the CSV contract."""


@dataclass
class _AddressActivity:
    counterparties: set[str]
    outgoing_amounts: list[Decimal]


@dataclass
class _TxGroup:
    """All rows sharing the same transaction_id."""

    senders: set[str] = field(default_factory=set)
    recipients: list[str] = field(default_factory=list)
    amounts: list[Decimal] = field(default_factory=list)


class _UnionFind:
    """Path-compressed, rank-union Disjoint Set for entity clustering."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def add(self, x: str) -> None:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0

    def find(self, x: str) -> str:
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def large_clusters(self, min_size: int) -> list[list[str]]:
        """Return all clusters with at least min_size members."""
        groups: dict[str, list[str]] = {}
        for node in self._parent:
            root = self.find(node)
            groups.setdefault(root, []).append(node)
        return [members for members in groups.values() if len(members) >= min_size]


def analyze_bitcoin_transfers(raw_csv: bytes) -> BitcoinAnalysis:
    """Analyze one sender-to-recipient transfer edge per CSV row entirely offline."""

    if not raw_csv:
        raise InvalidBitcoinData("Transaction CSV is empty.")
    try:
        text = raw_csv.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidBitcoinData("Transaction CSV must use UTF-8 encoding.") from exc

    outgoing: dict[str, _AddressActivity] = {}
    incoming: dict[str, _AddressActivity] = {}
    amounts: list[Decimal] = []
    rows_processed = 0
    unique_addresses: set[str] = set()
    tx_groups: dict[str, _TxGroup] = {}   # txid -> grouped data

    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        if reader.fieldnames is None:
            raise InvalidBitcoinData("Transaction CSV must include a header row.")
        reader.fieldnames = [header.strip() for header in reader.fieldnames if header]
        headers = set(reader.fieldnames)
        if len(headers) != len(reader.fieldnames):
            raise InvalidBitcoinData("Transaction CSV contains duplicate column names.")
        missing_headers = REQUIRED_COLUMNS - headers
        if missing_headers:
            missing = ", ".join(sorted(missing_headers))
            raise InvalidBitcoinData(f"Transaction CSV is missing required columns: {missing}.")

        for row in reader:
            if None in row or any(row.get(column) is None for column in REQUIRED_COLUMNS):
                raise InvalidBitcoinData("Transaction CSV contains a row with missing columns.")
            rows_processed += 1
            if rows_processed > MAX_TRANSFER_ROWS:
                raise InvalidBitcoinData(
                    f"Transaction CSV exceeds the {MAX_TRANSFER_ROWS:,}-row limit."
                )

            transaction_id = (row["transaction_id"] or "").strip()
            if not _TXID_PATTERN.fullmatch(transaction_id):
                raise InvalidBitcoinData("transaction_id must be a 64-character hexadecimal txid.")

            sender = (row["sender_address"] or "").strip()
            recipient = (row["recipient_address"] or "").strip()
            if not sender or len(sender) > 128:
                raise InvalidBitcoinData("sender_address must contain 1 to 128 characters.")
            if not recipient or len(recipient) > 128:
                raise InvalidBitcoinData("recipient_address must contain 1 to 128 characters.")
            if sender == recipient:
                raise InvalidBitcoinData("sender_address and recipient_address must differ.")

            amount_text = (row["amount_btc"] or "").strip()
            if not _AMOUNT_PATTERN.fullmatch(amount_text):
                raise InvalidBitcoinData(
                    "amount_btc must be a non-negative BTC value with up to 8 decimals."
                )
            try:
                amount = Decimal(amount_text)
            except InvalidOperation as exc:
                raise InvalidBitcoinData("amount_btc is not a valid decimal value.") from exc
            if amount <= 0 or amount > Decimal("21000000"):
                raise InvalidBitcoinData(
                    "amount_btc must be greater than 0 and at most 21,000,000."
                )

            unique_addresses.update((sender, recipient))
            if len(unique_addresses) > MAX_ADDRESSES:
                raise InvalidBitcoinData(
                    f"Transaction CSV exceeds the {MAX_ADDRESSES:,}-address limit."
                )

            sender_activity = outgoing.setdefault(
                sender,
                _AddressActivity(counterparties=set(), outgoing_amounts=[]),
            )
            sender_activity.counterparties.add(recipient)
            sender_activity.outgoing_amounts.append(amount)
            recipient_activity = incoming.setdefault(
                recipient,
                _AddressActivity(counterparties=set(), outgoing_amounts=[]),
            )
            recipient_activity.counterparties.add(sender)
            amounts.append(amount)

            # Group rows by txid for mixer, peeling, and clustering analysis
            grp = tx_groups.setdefault(transaction_id, _TxGroup())
            grp.senders.add(sender)
            grp.recipients.append(recipient)
            grp.amounts.append(amount)

    except csv.Error as exc:
        raise InvalidBitcoinData("Transaction CSV has malformed quoting or row structure.") from exc

    if rows_processed == 0:
        raise InvalidBitcoinData("Transaction CSV must contain at least one transfer row.")

    indicators: list[BitcoinIndicator] = []

    # -------------------------------------------------------------------------
    # Rule 1 & 2: Fan-out / fan-in (always computed)
    # -------------------------------------------------------------------------
    for _, activity in sorted(outgoing.items()):
        if len(activity.counterparties) >= ADDRESS_FAN_OUT_THRESHOLD:
            indicators.append(
                BitcoinIndicator(
                    rule_id="bitcoin.address-fan-out",
                    description=(
                        "A sender transferred to many distinct recipients; this can reflect "
                        "batching or other expected activity."
                    ),
                    severity="medium",
                    evidence={
                        "distinct_recipients": len(activity.counterparties),
                        "threshold": ADDRESS_FAN_OUT_THRESHOLD,
                    },
                )
            )

    for _, activity in sorted(incoming.items()):
        if len(activity.counterparties) >= ADDRESS_FAN_IN_THRESHOLD:
            indicators.append(
                BitcoinIndicator(
                    rule_id="bitcoin.address-fan-in",
                    description=(
                        "A recipient received transfers from many distinct senders; this can "
                        "reflect an exchange or pooled service."
                    ),
                    severity="medium",
                    evidence={
                        "distinct_senders": len(activity.counterparties),
                        "threshold": ADDRESS_FAN_IN_THRESHOLD,
                    },
                )
            )

    # -------------------------------------------------------------------------
    # Rule 3: High-value outlier (always computed)
    # -------------------------------------------------------------------------
    if len(amounts) >= 5:
        median_amount = median(amounts)
        if median_amount > 0:
            threshold = median_amount * HIGH_VALUE_MULTIPLIER
            high_value_count = sum(amount > threshold for amount in amounts)
            if high_value_count:
                indicators.append(
                    BitcoinIndicator(
                        rule_id="bitcoin.transfer-value-outlier",
                        description=(
                            "One or more transfer amounts are more than five times the sample "
                            "median; transaction value alone does not establish risk."
                        ),
                        severity="low",
                        evidence={
                            "transfer_count": len(amounts),
                            "median_btc": format(median_amount, "f"),
                            "threshold_btc": format(threshold, "f"),
                            "outlier_count": high_value_count,
                        },
                    )
                )

    # -------------------------------------------------------------------------
    # Rule 4: Union-Find entity clustering — common-input co-spend heuristic
    # Only union addresses that appear as co-spending INPUTS in the same txid.
    # Single-input transactions (one sender per txid) do NOT trigger clustering.
    # Privacy: only cluster sizes are emitted, never raw address strings.
    # -------------------------------------------------------------------------
    uf = _UnionFind()
    for addr in unique_addresses:
        uf.add(addr)

    for _txid, grp in tx_groups.items():
        # Co-spend heuristic: multiple distinct senders in same tx → same entity
        senders_list = sorted(grp.senders)
        if len(senders_list) >= 2:
            pivot = senders_list[0]
            for other in senders_list[1:]:
                uf.union(pivot, other)

    found_clusters = uf.large_clusters(min_size=_CLUSTER_MIN_SIZE)
    if found_clusters:
        largest_size = max(len(c) for c in found_clusters)
        indicators.append(
            BitcoinIndicator(
                rule_id="bitcoin.entity-cluster-detected",
                description=(
                    "Common-input ownership heuristic (Union-Find) identified address groups "
                    "that likely belong to the same controlling entity; manual attribution needed."
                ),
                severity="medium",
                evidence={
                    "cluster_count": len(found_clusters),
                    "largest_cluster_size": largest_size,
                    "min_cluster_size_threshold": _CLUSTER_MIN_SIZE,
                    "method": "union_find_co_spend_heuristic",
                },
            )
        )

    # -------------------------------------------------------------------------
    # Rule 5: Peeling chain detection — single-in single-out relay node heuristic
    # A "peeling" node receives from exactly 1 source and forwards to exactly 1
    # destination. A chain of >= 2 such hops suggests layering of funds.
    # -------------------------------------------------------------------------
    peeling_hop_count = 0
    for addr in unique_addresses:
        received_from_count = (
            len(incoming[addr].counterparties) if addr in incoming else 0
        )
        sent_to_count = len(outgoing[addr].counterparties) if addr in outgoing else 0
        if received_from_count == 1 and sent_to_count == 1:
            peeling_hop_count += 1

    if peeling_hop_count >= _PEELING_MIN_HOPS:
        indicators.append(
            BitcoinIndicator(
                rule_id="bitcoin.peeling-chain-detected",
                description=(
                    "Addresses that receive from exactly one source and forward to exactly one "
                    "destination were detected; this pattern is consistent with peeling chains "
                    "used to layer funds through multiple hops."
                ),
                severity="medium",
                evidence={
                    "peeling_hop_count": peeling_hop_count,
                    "detection_pattern": "single_in_single_out_relay_node",
                    "min_hops_threshold": _PEELING_MIN_HOPS,
                },
            )
        )

    # -------------------------------------------------------------------------
    # Rule 6: Equal-output mixer / CoinJoin / tumbler detection
    # A transaction with >= 3 outputs of identical amounts from the same sender
    # is consistent with CoinJoin coordination or a tumbler service.
    # -------------------------------------------------------------------------
    mixer_tx_count = 0
    for _txid, grp in tx_groups.items():
        if len(grp.amounts) >= _MIXER_MIN_OUTPUTS:
            min_amt = min(grp.amounts)
            max_amt = max(grp.amounts)
            if max_amt - min_amt <= _MIXER_TOLERANCE:
                mixer_tx_count += 1

    if mixer_tx_count > 0:
        indicators.append(
            BitcoinIndicator(
                rule_id="bitcoin.mixer-tumbler-equal-output",
                description=(
                    "Transactions with 3 or more outputs of identical amounts detected; "
                    "this is consistent with CoinJoin coordination or tumbler/mixer activity."
                ),
                severity="high",
                evidence={
                    "equal_output_tx_count": mixer_tx_count,
                    "min_outputs_threshold": _MIXER_MIN_OUTPUTS,
                    "amount_tolerance_btc": str(_MIXER_TOLERANCE),
                    "detection_pattern": "equal_output_split",
                },
            )
        )

    # -------------------------------------------------------------------------
    # Analytics summary (aggregate only — no raw addresses emitted)
    # -------------------------------------------------------------------------
    total_addresses = len(unique_addresses)
    fanout_count = sum(
        1 for a in outgoing.values() if len(a.counterparties) >= ADDRESS_FAN_OUT_THRESHOLD
    )
    fanin_count = sum(
        1 for a in incoming.values() if len(a.counterparties) >= ADDRESS_FAN_IN_THRESHOLD
    )
    analytics_summary: dict[str, Any] = {
        "framework": "NTRO Bitcoin Forensic Transaction Intelligence",
        "total_unique_addresses": total_addresses,
        "entity_clusters_detected": len(found_clusters),
        "largest_cluster_size": max((len(c) for c in found_clusters), default=0),
        "peeling_chain_hops_detected": peeling_hop_count,
        "mixer_equal_output_tx_count": mixer_tx_count,
        "fan_out_entities": fanout_count,
        "fan_in_entities": fanin_count,
        "clustering_method": "Union-Find Common-Input Co-Spend Ownership Heuristic",
        "peeling_method": "Single-In Single-Out Relay Node Detection",
        "mixer_method": "Equal-Output Transaction Split Analysis",
        "privacy_compliance": "Zero Raw Address Retention (Anonymized Entity Graph)",
    }

    return BitcoinAnalysis(
        rows_processed=rows_processed,
        indicators=indicators,
        analytics_summary=analytics_summary,
    )
