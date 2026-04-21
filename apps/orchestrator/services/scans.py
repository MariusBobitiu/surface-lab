from typing import Any

from db.postgres import get_db_connection
from schemas.scan import (
    FindingResponse,
    ScanDetailsResponse,
    ScanStepResponse,
    ScanSummaryResponse,
)


def get_scan_details(scan_id: str) -> ScanDetailsResponse:
    with get_db_connection() as connection:
        scan = fetch_scan(connection, scan_id)
        if scan is None:
            raise LookupError("Scan not found")

        steps = fetch_scan_steps(connection, scan_id)
        findings = fetch_findings(connection, scan_id)

    return ScanDetailsResponse(
        scan_id=str(scan["id"]),
        target=scan["target"],
        status=scan["status"],
        error_message=scan["error_message"],
        created_at=scan["created_at"],
        updated_at=scan["updated_at"],
        started_at=scan["started_at"],
        completed_at=scan["completed_at"],
        summary=build_summary(findings),
        steps=steps,
        findings=findings,
    )


def fetch_scan(connection, scan_id: str) -> dict[str, Any] | None:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, target, status, error_message, created_at, updated_at, started_at, completed_at
            FROM scans
            WHERE id = %s
            """,
            (scan_id,),
        )
        return cursor.fetchone()


def fetch_scan_steps(connection, scan_id: str) -> list[ScanStepResponse]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, tool_name, status, duration_ms, raw_metadata, created_at
            FROM scan_steps
            WHERE scan_id = %s
            ORDER BY created_at ASC
            """,
            (scan_id,),
        )
        rows = cursor.fetchall()

    return [
        ScanStepResponse(
            id=str(row["id"]),
            tool_name=row["tool_name"],
            status=row["status"],
            duration_ms=row["duration_ms"],
            raw_metadata=row["raw_metadata"] or {},
            created_at=row["created_at"],
        )
        for row in rows
    ]


def fetch_findings(connection, scan_id: str) -> list[FindingResponse]:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT id, tool_name, type, category, title, severity, confidence, evidence, details, created_at
            FROM findings
            WHERE scan_id = %s
            ORDER BY created_at ASC
            """,
            (scan_id,),
        )
        rows = cursor.fetchall()

    return [
        FindingResponse(
            id=str(row["id"]),
            tool_name=row["tool_name"],
            type=row["type"],
            category=row["category"],
            title=row["title"],
            severity=row["severity"],
            confidence=row["confidence"],
            evidence=row["evidence"],
            details=row["details"] or {},
            created_at=row["created_at"],
        )
        for row in rows
    ]


def build_summary(findings: list[FindingResponse]) -> ScanSummaryResponse:
    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()
        if severity in counts:
            counts[severity] += 1

    return ScanSummaryResponse(
        total=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
    )
