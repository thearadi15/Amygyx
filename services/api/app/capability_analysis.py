"""Local-only, bounded analyzers for the remaining platform capability prototypes."""

from __future__ import annotations

import csv
import io
import math
import re
import struct
import wave
from dataclasses import dataclass
from datetime import datetime
from statistics import fmean, pstdev
from typing import Literal

MAX_ROWS = 10_000
MAX_DURATION_SECONDS = 120
MAX_AUDIO_SAMPLE_RATE = 96_000


@dataclass(frozen=True)
class CapabilityIndicator:
    """A bounded, explainable review signal from a local analyzer."""

    rule_id: str
    description: str
    severity: Literal["informational", "low", "medium", "high"]
    evidence: dict[str, str | int | float | bool]


@dataclass(frozen=True)
class CapabilityAnalysis:
    """Non-retaining analysis summary shared by prototype capability endpoints."""

    records_processed: int
    summary: dict[str, str | int | float | bool]
    indicators: list[CapabilityIndicator]


class InvalidCapabilityInput(ValueError):
    """Raised when a capability upload is malformed or outside its supported profile."""


def _decode_utf8(data: bytes, name: str) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InvalidCapabilityInput(f"{name} must use UTF-8 encoding.") from exc


def _read_csv(data: bytes, required: set[str], name: str) -> list[dict[str, str]]:
    if not data:
        raise InvalidCapabilityInput(f"{name} is empty.")
    try:
        reader = csv.DictReader(io.StringIO(_decode_utf8(data, name), newline=""), strict=True)
        if reader.fieldnames is None:
            raise InvalidCapabilityInput(f"{name} must include a header row.")
        reader.fieldnames = [field.strip() for field in reader.fieldnames]
        if not all(reader.fieldnames):
            raise InvalidCapabilityInput(f"{name} contains an empty column name.")
        if len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise InvalidCapabilityInput(f"{name} contains duplicate column names.")
        missing = required - set(reader.fieldnames)
        if missing:
            raise InvalidCapabilityInput(
                f"{name} is missing required columns: {', '.join(sorted(missing))}."
            )
        rows: list[dict[str, str]] = []
        for row in reader:
            if None in row or any(row.get(field) is None for field in required):
                raise InvalidCapabilityInput(f"{name} contains a row with missing columns.")
            rows.append({key: (value or "").strip() for key, value in row.items() if key})
            if len(rows) > MAX_ROWS:
                raise InvalidCapabilityInput(f"{name} exceeds the {MAX_ROWS:,}-row limit.")
    except csv.Error as exc:
        raise InvalidCapabilityInput(f"{name} has malformed quoting or row structure.") from exc
    if not rows:
        raise InvalidCapabilityInput(f"{name} must contain at least one data row.")
    return rows


def _number(value: str, label: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise InvalidCapabilityInput(f"{label} must be numeric.") from exc
    if not math.isfinite(result):
        raise InvalidCapabilityInput(f"{label} must be a finite number.")
    return result


def _severity_for_net_benefit(net_benefit: float) -> Literal["low", "medium", "high"]:
    if net_benefit >= 1_000_000:
        return "high"
    if net_benefit >= 100_000:
        return "medium"
    return "low"


def _baseline_severity(value: str) -> Literal["informational", "low", "medium", "high"]:
    if value == "high":
        return "high"
    if value == "medium":
        return "medium"
    if value == "informational":
        return "informational"
    return "low"


def analyze_risk_investments(
    data: bytes,
    budget_usd: float | None = None,
) -> CapabilityAnalysis:
    """Rank control scenarios and optionally optimize a bounded budget."""

    rows = _read_csv(
        data,
        {
            "asset",
            "asset_value_usd",
            "annual_event_probability",
            "impact_fraction",
            "control",
            "annual_control_cost_usd",
            "risk_reduction_fraction",
        },
        "Risk investment CSV",
    )
    if budget_usd is not None and not 0 <= budget_usd <= 1_000_000:
        raise InvalidCapabilityInput("budget_usd must be from 0 to 1,000,000.")
    if budget_usd is not None and len(rows) > 100:
        raise InvalidCapabilityInput("Budget optimization supports at most 100 control options.")

    ranked: list[tuple[float, dict[str, str | int | float | bool]]] = []
    asset_losses: dict[str, float] = {}
    investment_keys: set[tuple[str, str]] = set()
    for row in rows:
        asset = row["asset"][:100]
        control = row["control"][:100]
        if not asset or not control:
            raise InvalidCapabilityInput("asset and control must not be empty.")
        if (asset, control) in investment_keys:
            raise InvalidCapabilityInput("Each asset/control investment option must be unique.")
        investment_keys.add((asset, control))
        asset_value = _number(row["asset_value_usd"], "asset_value_usd")
        probability = _number(row["annual_event_probability"], "annual_event_probability")
        impact = _number(row["impact_fraction"], "impact_fraction")
        cost = _number(row["annual_control_cost_usd"], "annual_control_cost_usd")
        reduction = _number(row["risk_reduction_fraction"], "risk_reduction_fraction")
        if not 0 <= asset_value <= 1_000_000_000_000 or not 0 <= cost <= 1_000_000_000_000:
            raise InvalidCapabilityInput(
                "Asset value and annual control cost must be from 0 to 1 trillion USD."
            )
        if not 0 <= probability <= 1 or not 0 <= impact <= 1 or not 0 <= reduction <= 1:
            raise InvalidCapabilityInput(
                "Probability, impact_fraction, and risk_reduction_fraction must be from 0 to 1."
            )
        expected_loss = asset_value * probability * impact
        avoided_loss = expected_loss * reduction
        net_benefit = avoided_loss - cost
        roi: float | str = (avoided_loss - cost) / cost if cost > 0 else "not_applicable"
        if not all(math.isfinite(value) for value in (expected_loss, avoided_loss, net_benefit)):
            raise InvalidCapabilityInput("Risk calculation exceeded the supported numeric range.")
        if isinstance(roi, float) and not math.isfinite(roi):
            raise InvalidCapabilityInput("Risk calculation exceeded the supported numeric range.")
        if asset in asset_losses and not math.isclose(
            asset_losses[asset],
            expected_loss,
            rel_tol=1e-9,
        ):
            raise InvalidCapabilityInput(
                "Rows for the same asset must use identical value, probability, and impact."
            )
        asset_losses[asset] = expected_loss
        ranked.append(
            (
                net_benefit,
                {
                    "asset": asset,
                    "control": control,
                    "annual_expected_loss_usd": round(expected_loss, 2),
                    "annual_loss_avoided_usd": round(avoided_loss, 2),
                    "annual_control_cost_usd": round(cost, 2),
                    "annual_net_benefit_usd": round(net_benefit, 2),
                    "estimated_roi": round(roi, 3) if isinstance(roi, float) else roi,
                },
            )
        )

    selected_options: set[tuple[str, str]] = set()
    optimizer_granularity = 10
    if budget_usd is not None:
        capacity = int(budget_usd // optimizer_granularity)
        best_avoided_loss = [0.0] * (capacity + 1)
        decisions: list[bytearray] = []
        optimizer_options = sorted(
            enumerate(ranked),
            key=lambda item: (str(item[1][1]["control"]), str(item[1][1]["asset"])),
        )
        for _, (_, evidence) in optimizer_options:
            cost_units = math.ceil(
                float(evidence["annual_control_cost_usd"]) / optimizer_granularity
            )
            selected = bytearray(capacity + 1)
            avoided_loss = float(evidence["annual_loss_avoided_usd"])
            if cost_units <= capacity:
                for available in range(capacity, cost_units - 1, -1):
                    candidate = best_avoided_loss[available - cost_units] + avoided_loss
                    if candidate > best_avoided_loss[available]:
                        best_avoided_loss[available] = candidate
                        selected[available] = 1
            decisions.append(selected)

        available = capacity
        for position in range(len(optimizer_options) - 1, -1, -1):
            if decisions[position][available]:
                _, (_, evidence) = optimizer_options[position]
                selected_options.add((str(evidence["asset"]), str(evidence["control"])))
                available -= math.ceil(
                    float(evidence["annual_control_cost_usd"]) / optimizer_granularity
                )

    ranked.sort(
        key=lambda item: (
            (
                (str(item[1]["asset"]), str(item[1]["control"])) not in selected_options
                if budget_usd is not None
                else False
            ),
            -item[0],
            str(item[1]["control"]),
            str(item[1]["asset"]),
        )
    )
    indicators = [
        CapabilityIndicator(
            rule_id="risk.investment-positive-net-benefit"
            if net_benefit > 0
            else "risk.investment-negative-net-benefit",
            description=(
                "Estimated control investment has positive annual net benefit under supplied "
                "assumptions; validate probabilities and costs before budgeting."
                if net_benefit > 0
                else "Estimated control cost exceeds modeled annual loss reduction under "
                "supplied assumptions; this is not a recommendation to accept the security risk."
            ),
            severity=_severity_for_net_benefit(net_benefit),
            evidence={
                **item,
                **(
                    {
                        "selected_for_budget": (
                            str(item["asset"]),
                            str(item["control"]),
                        )
                        in selected_options,
                        "budget_granularity_usd": optimizer_granularity,
                    }
                    if budget_usd is not None
                    else {}
                ),
            },
        )
        for net_benefit, item in ranked[:100]
    ]
    optimization_summary: dict[str, str | int | float | bool] = {}
    if budget_usd is not None:
        optimization_summary = {
            "budget_usd": budget_usd,
            "optimizer": "0_1_knapsack_max_avoided_loss",
            "optimizer_cost_granularity_usd": optimizer_granularity,
            "selected_control_options": len(selected_options),
            "projected_annual_loss_avoided_usd": round(
                sum(
                    float(evidence["annual_loss_avoided_usd"])
                    for _, evidence in ranked
                    if (str(evidence["asset"]), str(evidence["control"])) in selected_options
                ),
                2,
            ),
            "optimization_is_exact_at_disclosed_cost_granularity": True,
        }
    return CapabilityAnalysis(
        records_processed=len(rows),
        summary={
            "model": "annual_expected_loss_v1",
            "total_annual_expected_loss_usd": round(sum(asset_losses.values()), 2),
            "ranked_investments": len(ranked),
            **optimization_summary,
        },
        indicators=indicators,
    )


def analyze_network_forecast(data: bytes) -> CapabilityAnalysis:
    """Project one next-period event count from an ordered event-count time series."""

    rows = _read_csv(data, {"timestamp", "event_count"}, "Network event time-series CSV")
    if len(rows) < 8:
        raise InvalidCapabilityInput("Network forecasting requires at least 8 observations.")
    observations: list[tuple[datetime, float]] = []
    for row in rows:
        try:
            timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise InvalidCapabilityInput("timestamp must be ISO 8601 date/time.") from exc
        if timestamp.utcoffset() is None:
            raise InvalidCapabilityInput("timestamp must include a timezone offset.")
        value = _number(row["event_count"], "event_count")
        if not 0 <= value <= 1_000_000_000_000:
            raise InvalidCapabilityInput("event_count must be from 0 to 1 trillion.")
        if observations and timestamp <= observations[-1][0]:
            raise InvalidCapabilityInput("timestamps must be strictly increasing.")
        observations.append((timestamp, value))
    intervals = {
        current[0] - previous[0]
        for previous, current in zip(observations, observations[1:], strict=False)
    }
    if len(intervals) != 1:
        raise InvalidCapabilityInput("timestamps must use evenly spaced intervals.")

    values = [value for _, value in observations]
    x_mean = (len(values) - 1) / 2
    y_mean = fmean(values)
    denominator = sum((index - x_mean) ** 2 for index in range(len(values)))
    slope = (
        sum((index - x_mean) * (value - y_mean) for index, value in enumerate(values)) / denominator
    )
    intercept = y_mean - slope * x_mean
    predicted = max(0.0, intercept + slope * len(values))
    residuals = [value - (intercept + slope * index) for index, value in enumerate(values)]
    residual_spread = pstdev(residuals)
    elevated = slope > 0 and predicted > y_mean + 2 * residual_spread
    summary: dict[str, str | int | float | bool] = {
        "method": "ordinary_least_squares_one_step",
        "observations": len(values),
        "mean_event_count": round(y_mean, 3),
        "trend_per_period": round(slope, 3),
        "next_period_projection": round(predicted, 3),
        "residual_spread": round(residual_spread, 3),
        "trend_flag": elevated,
    }
    indicators: list[CapabilityIndicator] = []
    if elevated:
        indicators.append(
            CapabilityIndicator(
                rule_id="network.forecast-elevated-trend",
                description=(
                    "The one-step linear projection is elevated relative to this sample. "
                    "This small-sample trend is not an attack prediction."
                ),
                severity="medium",
                evidence=summary,
            )
        )
    return CapabilityAnalysis(
        records_processed=len(rows),
        summary=summary,
        indicators=indicators,
    )


def analyze_network_compliance(data: bytes) -> CapabilityAnalysis:
    """Check a limited, versioned set of Cisco IOS configuration baselines."""

    text = _decode_utf8(data, "Cisco IOS configuration")
    if not text.strip() or len(text) > 1_048_576:
        raise InvalidCapabilityInput("Cisco IOS configuration is empty or exceeds the limit.")
    lowered = text.lower()
    checks: list[tuple[str, bool, str, str]] = [
        (
            "compliance.cisco-aaa",
            "aaa new-model" in lowered,
            "Enable AAA new-model and review the configured authentication policy.",
            "medium",
        ),
        (
            "compliance.cisco-enable-secret",
            re.search(r"(?m)^\s*enable\s+secret\s+", lowered) is not None
            and re.search(r"(?m)^\s*enable\s+password\s+", lowered) is None,
            "Use an enable secret and remove legacy enable password configuration.",
            "high",
        ),
        (
            "compliance.cisco-ssh-only",
            re.search(r"(?m)^\s*transport\s+input\s+ssh\s*$", lowered) is not None
            and "transport input telnet" not in lowered
            and "transport input all" not in lowered,
            "Restrict VTY transport to SSH; Telnet is not encrypted.",
            "high",
        ),
        (
            "compliance.cisco-vty-timeout",
            re.search(r"(?m)^\s*exec-timeout\s+(?:[1-9]\d*|0\s+[1-9]\d*)", lowered) is not None,
            "Set a non-zero VTY exec-timeout to limit unattended sessions.",
            "medium",
        ),
        (
            "compliance.cisco-logging",
            re.search(r"(?m)^\s*logging\s+host\s+", lowered) is not None
            and "service timestamps log datetime" in lowered,
            "Configure a remote logging host and timestamps for traceable events.",
            "low",
        ),
        (
            "compliance.cisco-snmp-public-community",
            re.search(r"(?m)^\s*snmp-server\s+community\s+(?:public|private)\b", lowered) is None,
            "Remove default public/private SNMP communities and use a managed secure SNMP policy.",
            "high",
        ),
    ]
    indicators = [
        CapabilityIndicator(
            rule_id=rule_id,
            description=description,
            severity=_baseline_severity(severity),
            evidence={"profile": "cisco-ios-baseline-v1", "check_passed": passed},
        )
        for rule_id, passed, description, severity in checks
        if not passed
    ]
    return CapabilityAnalysis(
        records_processed=len(text.splitlines()),
        summary={
            "profile": "cisco-ios-baseline-v1",
            "checks_run": len(checks),
            "checks_passed": len(checks) - len(indicators),
            "checks_failed": len(indicators),
        },
        indicators=indicators,
    )


def analyze_ipsec_configuration(data: bytes) -> CapabilityAnalysis:
    """Assess a limited set of strongSwan ipsec.conf proposal and secret checks."""

    text = _decode_utf8(data, "strongSwan configuration")
    if not text.strip() or len(text) > 1_048_576:
        raise InvalidCapabilityInput("strongSwan configuration is empty or exceeds the limit.")
    lowered = text.lower()
    key_exchange = re.findall(r"(?im)^\s*keyexchange\s*=\s*([^\s#;]+)", lowered)
    proposals = re.findall(r"(?im)^\s*(ike|esp)\s*=\s*([^\s#;]+)", lowered)
    weak_algorithms = re.compile(r"\b(?:3des|des|md5|sha1|modp1024|modp768)\b")
    weak_proposals = [value for _, value in proposals if weak_algorithms.search(value)]
    checks: list[tuple[str, bool, str, str]] = [
        (
            "ipsec.ikev2-only",
            bool(key_exchange) and all(value == "ikev2" for value in key_exchange),
            (
                "Use IKEv2 for every configured connection; legacy IKEv1 needs explicit "
                "exception review."
            ),
            "high",
        ),
        (
            "ipsec.explicit-modern-proposals",
            bool(proposals) and len({name for name, _ in proposals}) == 2,
            "Define explicit IKE and ESP cryptographic proposals for each connection.",
            "medium",
        ),
        (
            "ipsec.no-known-weak-algorithms",
            not weak_proposals,
            "Replace weak DES/3DES, MD5, SHA-1, or undersized MODP proposals.",
            "high",
        ),
        (
            "ipsec.no-inline-secrets",
            re.search(r"(?im)^\s*:\s*psk\s+['\"]?[^%#\s]", text) is None,
            "Do not store plaintext pre-shared secrets in the supplied configuration file.",
            "high",
        ),
    ]
    indicators = [
        CapabilityIndicator(
            rule_id=rule_id,
            description=description,
            severity=_baseline_severity(severity),
            evidence={
                "profile": "strongSwan-ipsec-baseline-v1",
                "check_passed": passed,
                **(
                    {"weak_proposals_found": len(weak_proposals)}
                    if rule_id == "ipsec.no-known-weak-algorithms"
                    else {}
                ),
            },
        )
        for rule_id, passed, description, severity in checks
        if not passed
    ]
    return CapabilityAnalysis(
        records_processed=len(text.splitlines()),
        summary={
            "profile": "strongSwan-ipsec-baseline-v1",
            "checks_run": len(checks),
            "checks_passed": len(checks) - len(indicators),
            "checks_failed": len(indicators),
        },
        indicators=indicators,
    )


def analyze_document_structure(data: bytes, filename: str) -> CapabilityAnalysis:
    """Check PDF/PNG/JPEG structural warning signals without identifying a person."""

    lower_name = filename.lower()
    indicators: list[CapabilityIndicator] = []
    if lower_name.endswith(".pdf"):
        if not data.startswith(b"%PDF-"):
            raise InvalidCapabilityInput("PDF signature is missing.")
        if b"%%EOF" not in data[-2048:]:
            indicators.append(
                CapabilityIndicator(
                    rule_id="identity.document-missing-pdf-eof",
                    description="The PDF trailer marker is missing near the end of the file.",
                    severity="medium",
                    evidence={"format": "pdf"},
                )
            )
        eof_count = data.count(b"%%EOF")
        if eof_count > 1:
            indicators.append(
                CapabilityIndicator(
                    rule_id="identity.document-multiple-pdf-revisions",
                    description=(
                        "Multiple PDF end markers may indicate incremental revisions; this is "
                        "common in legitimate edited or signed PDFs."
                    ),
                    severity="low",
                    evidence={"format": "pdf", "pdf_revision_markers": eof_count},
                )
            )
        active_tokens = sum(data.count(token) for token in (b"/JavaScript", b"/JS", b"/Launch"))
        if active_tokens:
            indicators.append(
                CapabilityIndicator(
                    rule_id="identity.document-pdf-active-content",
                    description="The PDF contains active-content markers that need safe review.",
                    severity="medium",
                    evidence={"format": "pdf", "active_content_markers": active_tokens},
                )
            )
        summary: dict[str, str | int | float | bool] = {
            "format": "pdf",
            "bytes": len(data),
            "revision_markers": eof_count,
        }
    elif lower_name.endswith(".png"):
        if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) < 33:
            raise InvalidCapabilityInput("PNG signature or image header is invalid.")
        if b"IEND" not in data[-32:]:
            indicators.append(
                CapabilityIndicator(
                    rule_id="identity.document-image-truncated",
                    description="The PNG end marker is missing near the end of the file.",
                    severity="medium",
                    evidence={"format": "png"},
                )
            )
        summary = {"format": "png", "bytes": len(data)}
    elif lower_name.endswith((".jpg", ".jpeg")):
        if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
            raise InvalidCapabilityInput("JPEG start or end marker is missing.")
        summary = {"format": "jpeg", "bytes": len(data)}
    else:
        raise InvalidCapabilityInput("Supported document file types are PDF, PNG, and JPEG.")
    return CapabilityAnalysis(records_processed=1, summary=summary, indicators=indicators)


def analyze_video_event_export(data: bytes) -> CapabilityAnalysis:
    """Summarize non-biometric event exports from already-authorized CCTV analytics."""

    rows = _read_csv(
        data,
        {"timestamp", "camera_id", "event_type", "confidence"},
        "CCTV event export CSV",
    )
    per_camera: dict[str, list[dict[str, str]]] = {}
    indicators: list[CapabilityIndicator] = []
    for row in rows:
        try:
            timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
        except ValueError as exc:
            raise InvalidCapabilityInput("timestamp must be ISO 8601 date/time.") from exc
        if timestamp.utcoffset() is None:
            raise InvalidCapabilityInput("timestamp must include a timezone offset.")
        confidence = _number(row["confidence"], "confidence")
        if not 0 <= confidence <= 1:
            raise InvalidCapabilityInput("confidence must be between 0 and 1.")
        camera_id = row["camera_id"]
        event_type = row["event_type"].lower()
        if not camera_id or len(camera_id) > 100 or not event_type or len(event_type) > 100:
            raise InvalidCapabilityInput(
                "camera_id and event_type must contain 1 to 100 characters."
            )
        per_camera.setdefault(camera_id, []).append(
            {
                "event_type": event_type,
                "confidence": str(confidence),
                "hour": str(timestamp.hour),
            }
        )
        if confidence < 0.5:
            indicators.append(
                CapabilityIndicator(
                    rule_id="video.event-low-model-confidence",
                    description=(
                        "An existing camera system reported a low-confidence event; it needs "
                        "human review and is not a verified observation."
                    ),
                    severity="low",
                    evidence={
                        "camera_id": camera_id[:100],
                        "event_type": event_type[:100],
                        "reported_confidence": round(confidence, 3),
                    },
                )
            )
    for camera_id, events in sorted(per_camera.items()):
        after_hours_count = sum(
            int(event["hour"]) < 6 or int(event["hour"]) >= 22 for event in events
        )
        if after_hours_count:
            indicators.append(
                CapabilityIndicator(
                    rule_id="video.after-hours-event-summary",
                    description=(
                        "Camera event export includes events outside the 06:00–22:00 local-time "
                        "window; confirm the site's schedule and timezone."
                    ),
                    severity="informational",
                    evidence={
                        "camera_id": camera_id[:100],
                        "after_hours_events": after_hours_count,
                        "timezone": "timestamp-local-offset-required",
                    },
                )
            )
    return CapabilityAnalysis(
        records_processed=len(rows),
        summary={
            "event_records": len(rows),
            "camera_count": len(per_camera),
            "analysis": "metadata-only; no video frames or biometric identification",
        },
        indicators=indicators[:100],
    )


def analyze_voice_audio(data: bytes) -> CapabilityAnalysis:
    """Inspect WAV signal integrity only; this does not detect cloned or impersonated speech."""

    if not data:
        raise InvalidCapabilityInput("WAV audio file is empty.")
    try:
        with wave.open(io.BytesIO(data), "rb") as audio:
            channels = audio.getnchannels()
            sample_width = audio.getsampwidth()
            sample_rate = audio.getframerate()
            frame_count = audio.getnframes()
            compression = audio.getcomptype()
            if channels not in {1, 2} or sample_width not in {1, 2} or compression != "NONE":
                raise InvalidCapabilityInput(
                    "Only uncompressed mono/stereo 8-bit or 16-bit PCM WAV is supported."
                )
            if not 8_000 <= sample_rate <= MAX_AUDIO_SAMPLE_RATE:
                raise InvalidCapabilityInput("WAV sample rate must be between 8 kHz and 96 kHz.")
            duration = frame_count / sample_rate
            if not 0 < duration <= MAX_DURATION_SECONDS:
                raise InvalidCapabilityInput("WAV duration must be between 0 and 120 seconds.")
            frames = audio.readframes(frame_count)
            expected_bytes = frame_count * channels * sample_width
            if len(frames) != expected_bytes:
                raise InvalidCapabilityInput("WAV audio data is truncated.")
    except (wave.Error, EOFError, struct.error) as exc:
        raise InvalidCapabilityInput("Audio upload is not a supported PCM WAV file.") from exc

    if sample_width == 1:
        samples = (sample - 128 for sample in frames)
        peak = 127
    else:
        samples = (sample[0] for sample in struct.iter_unpack("<h", frames))
        peak = 32767
    total = 0
    count = 0
    clipped = 0
    silent = 0
    threshold = max(1, int(peak * 0.005))
    for sample in samples:
        magnitude = abs(sample)
        total += sample * sample
        count += 1
        if magnitude >= peak - 1:
            clipped += 1
        if magnitude <= threshold:
            silent += 1
    if count == 0:
        raise InvalidCapabilityInput("WAV contains no audio samples.")
    clipped_fraction = clipped / count
    silent_fraction = silent / count
    rms = math.sqrt(total / count) / peak
    indicators: list[CapabilityIndicator] = []
    if clipped_fraction >= 0.01:
        indicators.append(
            CapabilityIndicator(
                rule_id="voice.audio-clipping",
                description="Audio contains substantial clipped samples that may obscure analysis.",
                severity="low",
                evidence={"clipped_sample_fraction": round(clipped_fraction, 4)},
            )
        )
    if silent_fraction >= 0.95 or rms < 0.005:
        indicators.append(
            CapabilityIndicator(
                rule_id="voice.audio-low-signal",
                description=(
                    "Audio is mostly silent or very low level and is unsuitable for review."
                ),
                severity="low",
                evidence={
                    "near_silence_fraction": round(silent_fraction, 4),
                    "normalized_rms": round(rms, 5),
                },
            )
        )
    return CapabilityAnalysis(
        records_processed=frame_count,
        summary={
            "format": "pcm-wav",
            "channels": channels,
            "sample_rate_hz": sample_rate,
            "duration_seconds": round(duration, 3),
            "normalized_rms": round(rms, 5),
            "spoof_detection": "not_available_in_offline_signal_integrity_profile",
        },
        indicators=indicators,
    )


def dispatch_capability_analysis(
    capability_id: str,
    data: bytes,
    filename: str,
    budget_usd: float | None = None,
) -> CapabilityAnalysis:
    """Validate the supported local analyzer profile for a capability ID."""

    if capability_id == "risk":
        return analyze_risk_investments(data, budget_usd)
    if capability_id == "forecasting":
        return analyze_network_forecast(data)
    if capability_id == "compliance":
        return analyze_network_compliance(data)
    if capability_id == "ipsec":
        return analyze_ipsec_configuration(data)
    if capability_id == "identity":
        return analyze_document_structure(data, filename)
    if capability_id == "video":
        return analyze_video_event_export(data)
    if capability_id == "voice":
        if not filename.lower().endswith(".wav"):
            raise InvalidCapabilityInput("Only PCM WAV audio is supported by this offline profile.")
        return analyze_voice_audio(data)
    raise InvalidCapabilityInput("Unknown local analysis capability.")
