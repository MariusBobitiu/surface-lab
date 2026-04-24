from dataclasses import dataclass, field
from typing import Any

from schemas.scan import EvidenceResponse, FindingResponse, ScanStepResponse, SignalResponse


@dataclass(frozen=True)
class SignalValue:
    key: str
    value: Any
    confidence: str
    source: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class BaselineContext:
    scan_id: str
    target_input: str
    canonical_url: str
    redirected: bool
    findings: list[FindingResponse] = field(default_factory=list)
    evidence: list[EvidenceResponse] = field(default_factory=list)
    steps: list[ScanStepResponse] = field(default_factory=list)
    signal_map: dict[str, SignalValue] = field(default_factory=dict)

    def has_signal(self, key: str) -> bool:
        return key in self.signal_map

    def signal_is_true(self, key: str) -> bool:
        signal = self.signal_map.get(key)
        return signal is not None and signal.value is True

    def signal_value(self, key: str, default: Any = None) -> Any:
        signal = self.signal_map.get(key)
        if signal is None:
            return default
        return signal.value

    def signal_confidence(self, key: str, default: str | None = None) -> str | None:
        signal = self.signal_map.get(key)
        if signal is None:
            return default
        return signal.confidence

    @property
    def routing_signals(self) -> dict[str, SignalValue]:
        return {
            key: value
            for key, value in self.signal_map.items()
            if key.startswith(("framework.", "technology.", "assets.", "surface.", "hosting.", "tooling."))
        }

    @property
    def posture_signals(self) -> dict[str, SignalValue]:
        return {key: value for key, value in self.signal_map.items() if key.startswith("security.")}

    @property
    def exposure_signals(self) -> dict[str, SignalValue]:
        return {key: value for key, value in self.signal_map.items() if key.startswith("exposure.")}

    @property
    def context_signals(self) -> dict[str, SignalValue]:
        return {
            key: value
            for key, value in self.signal_map.items()
            if key.startswith(("hosting.", "transport.", "header."))
        }

    def planner_signal_summary(self) -> list[dict[str, Any]]:
        prioritized_keys = sorted(
            self.signal_map,
            key=lambda key: (
                0 if key.startswith(("framework.", "assets.", "surface.", "exposure.")) else 1,
                0 if key.startswith(("technology.", "hosting.", "tooling.")) else 1,
                key,
            ),
        )
        return [
            {
                "key": key,
                "value": self.signal_map[key].value,
                "confidence": self.signal_map[key].confidence,
                "source": self.signal_map[key].source,
            }
            for key in prioritized_keys
        ]

    def planner_finding_summary(self, limit: int = 8) -> list[dict[str, Any]]:
        return [
            {
                "type": finding.type,
                "category": finding.category,
                "title": finding.title,
                "summary": finding.summary,
                "severity": finding.severity,
                "confidence": finding.confidence,
            }
            for finding in self.findings[:limit]
        ]

    def planner_evidence_summary(self, limit: int = 6) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        for item in self.evidence[:limit]:
            selected.append(
                {
                    "id": item.id,
                    "kind": item.kind,
                    "target": item.target,
                    "data_keys": sorted((item.data or {}).keys())[:6],
                }
            )
        return selected


def build_baseline_context(
    scan: dict[str, Any],
    steps: list[ScanStepResponse],
    findings: list[FindingResponse],
    signals: list[SignalResponse],
    evidence: list[EvidenceResponse],
) -> BaselineContext:
    signal_map = _build_signal_map(signals, findings, steps)
    canonical_url = _resolve_canonical_url(scan, signal_map, evidence, steps)
    redirected = bool(signal_map.get("transport.redirected", SignalValue("", False, "", "")).value)
    if not redirected and canonical_url and canonical_url != scan["target"]:
        redirected = True

    return BaselineContext(
        scan_id=str(scan["id"]),
        target_input=scan["target"],
        canonical_url=canonical_url or scan["target"],
        redirected=redirected,
        findings=findings,
        evidence=evidence,
        steps=steps,
        signal_map=signal_map,
    )


def _build_signal_map(
    signals: list[SignalResponse],
    findings: list[FindingResponse],
    steps: list[ScanStepResponse],
) -> dict[str, SignalValue]:
    signal_map: dict[str, SignalValue] = {}

    for signal in signals:
        signal_map[signal.key] = SignalValue(
            key=signal.key,
            value=signal.value,
            confidence=signal.confidence,
            source=signal.source,
            evidence_refs=tuple(signal.evidence_refs),
        )

    if signal_map:
        return signal_map

    _derive_legacy_signals_from_findings(signal_map, findings)
    _derive_legacy_signals_from_steps(signal_map, steps)
    return signal_map


def _resolve_canonical_url(
    scan: dict[str, Any],
    signal_map: dict[str, SignalValue],
    evidence: list[EvidenceResponse],
    steps: list[ScanStepResponse],
) -> str:
    canonical_signal = signal_map.get("transport.canonical_url")
    if canonical_signal is not None and isinstance(canonical_signal.value, str) and canonical_signal.value:
        return canonical_signal.value

    for item in evidence:
        if item.kind == "redirect_chain":
            final_url = (item.data or {}).get("final_url")
            if isinstance(final_url, str) and final_url:
                return final_url

    for step in steps:
        raw_metadata = step.raw_metadata or {}
        metadata = raw_metadata.get("metadata", {})
        if step.tool_name == "targeting/v1":
            canonical_target = metadata.get("canonical_target")
            if isinstance(canonical_target, str) and canonical_target:
                return canonical_target
        final_url = metadata.get("final_url")
        if isinstance(final_url, str) and final_url:
            return final_url

    return scan["target"]


def _derive_legacy_signals_from_findings(signal_map: dict[str, SignalValue], findings: list[FindingResponse]) -> None:
    for finding in findings:
        combined = " ".join(
            [
                finding.title or "",
                finding.summary or "",
                finding.evidence or "",
                str(finding.details or {}),
            ]
        ).lower()

        if "wordpress" in combined:
            signal_map.setdefault("framework.wordpress", SignalValue("framework.wordpress", True, "medium", "legacy.findings"))
        if "next.js" in combined or "__next" in combined or "nextjs" in combined:
            signal_map.setdefault("framework.nextjs", SignalValue("framework.nextjs", True, "medium", "legacy.findings"))
            signal_map.setdefault("assets.next_static", SignalValue("assets.next_static", True, "medium", "legacy.findings"))
        if ".env" in combined:
            signal_map.setdefault("exposure.env_file", SignalValue("exposure.env_file", True, "high", "legacy.findings"))
        if ".git/config" in combined:
            signal_map.setdefault("exposure.git_config", SignalValue("exposure.git_config", True, "high", "legacy.findings"))


def _derive_legacy_signals_from_steps(signal_map: dict[str, SignalValue], steps: list[ScanStepResponse]) -> None:
    for step in steps:
        raw_metadata = step.raw_metadata or {}
        metadata = raw_metadata.get("metadata", {})
        final_url = metadata.get("final_url")
        if isinstance(final_url, str) and final_url:
            signal_map.setdefault("transport.canonical_url", SignalValue("transport.canonical_url", final_url, "medium", "legacy.scan_steps"))

        if metadata.get("http_redirects_to_https") is True:
            signal_map.setdefault(
                "security.http_redirects_to_https",
                SignalValue("security.http_redirects_to_https", True, "medium", "legacy.scan_steps"),
            )
        if metadata.get("https_reachable") is True:
            signal_map.setdefault("security.https", SignalValue("security.https", True, "medium", "legacy.scan_steps"))
        if metadata.get("certificate_valid") is True:
            signal_map.setdefault(
                "security.tls.cert_valid",
                SignalValue("security.tls.cert_valid", True, "medium", "legacy.scan_steps"),
            )
