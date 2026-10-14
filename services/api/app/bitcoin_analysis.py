"""Bounded, offline analysis of Bitcoin transfer-edge CSV data."""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from statistics import median
from typing import Literal

BITCOIN_RULESET_VERSION = "bitcoin-transfer-rules-v1"
MAX_TRANSFER_ROWS = 10_000
MAX_ADDRESSES = 20_000
ADDRESS_FAN_OUT_THRESHOLD = 10
ADDRESS_FAN_IN_THRESHOLD = 10
HIGH_VALUE_MULTIPLIER = Decimal(5)
REQUIRED_COLUMNS = {"transaction_id", "sender_address", "recipient_address", "amount_btc"}
_TXID_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
_AMOUNT_PATTERN = re.compile(r"^(?:0|[1-9][0-9]{0,7})(?:\.[0-9]{1,8})?$")


@dataclass(frozen=True)
class BitcoinIndicator:
    """One explainable transaction-graph signal requiring human review."""

    rule_id: str
    description: str
    severity: Literal["low", "medium", "high"]
    evidence: dict[str, str | int]


@dataclass(frozen=True)
class BitcoinAnalysis:
    """Aggregate-only output; raw transaction IDs and addresses are not retained."""

    rows_processed: int
    indicators: list[BitcoinIndicator]


class InvalidBitcoinData(ValueError):
    """Raised when uploaded transfer-edge data violates the CSV contract."""


@dataclass
class _AddressActivity:
    counterparties: set[str]
    outgoing_amounts: list[Decimal]


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
    except csv.Error as exc:
        raise InvalidBitcoinData("Transaction CSV has malformed quoting or row structure.") from exc

    if rows_processed == 0:
        raise InvalidBitcoinData("Transaction CSV must contain at least one transfer row.")

    indicators: list[BitcoinIndicator] = []
    for _, activity in sorted(outgoing.items()):
        counterpart_count = len(activity.counterparties)
        if counterpart_count >= ADDRESS_FAN_OUT_THRESHOLD:
            indicators.append(
                BitcoinIndicator(
                    rule_id="bitcoin.address-fan-out",
                    description=(
                        "A sender transferred to many distinct recipients; this can reflect "
                        "batching or other expected activity."
                    ),
                    severity="medium",
                    evidence={
                        "distinct_recipients": counterpart_count,
                        "threshold": ADDRESS_FAN_OUT_THRESHOLD,
                    },
                )
            )

    for _, activity in sorted(incoming.items()):
        counterpart_count = len(activity.counterparties)
        if counterpart_count >= ADDRESS_FAN_IN_THRESHOLD:
            indicators.append(
                BitcoinIndicator(
                    rule_id="bitcoin.address-fan-in",
                    description=(
                        "A recipient received transfers from many distinct senders; this can "
                        "reflect an exchange or pooled service."
                    ),
                    severity="medium",
                    evidence={
                        "distinct_senders": counterpart_count,
                        "threshold": ADDRESS_FAN_IN_THRESHOLD,
                    },
                )
            )

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

    return BitcoinAnalysis(rows_processed=rows_processed, indicators=indicators)
