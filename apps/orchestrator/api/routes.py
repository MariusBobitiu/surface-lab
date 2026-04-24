from queue import Empty
import logging

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
import grpc
import psycopg

from services.event_bus import format_sse_data, subscribe, unsubscribe
from grpc_clients.tool_client import run_baseline_scan
from schemas.scan import EnrichedReportResponse, ScanDetailsResponse, ScanReportResponse, ScanRequest, ScanResponse
from services.reports import get_scan_report
from services.scans import get_scan_details
from services.targets import TargetValidationError, validate_scan_target
from services.workflow_runner import run_or_wait_scan_workflow, start_scan_workflow


router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/scans", response_model=ScanResponse)
def create_scan(request: ScanRequest) -> ScanResponse:
    logger.info("create scan requested target=%s", request.target)
    try:
        target = validate_scan_target(request.target)
    except TargetValidationError as exc:
        logger.warning("create scan rejected target=%s error=%s", request.target, exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = run_baseline_scan(target)
    except grpc.RpcError as exc:
        detail = exc.details() or "Failed to call scanner service"
        logger.exception("scanner baseline gRPC call failed target=%s detail=%s", target, detail)
        raise HTTPException(status_code=500, detail=detail) from exc

    start_scan_workflow(result["scan_id"])
    logger.info("create scan accepted scan_id=%s status=%s target=%s", result["scan_id"], result["status"], target)

    return ScanResponse(scan_id=result["scan_id"], status=result["status"])


@router.get("/scans/{scan_id}", response_model=ScanDetailsResponse)
def read_scan(scan_id: str) -> ScanDetailsResponse:
    logger.info("read scan requested scan_id=%s", scan_id)
    try:
        scan = get_scan_details(scan_id)
    except LookupError as exc:
        logger.warning("read scan not found scan_id=%s", scan_id)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        logger.exception("read scan database error scan_id=%s", scan_id)
        raise HTTPException(status_code=500, detail="Failed to fetch scan") from exc

    logger.info("read scan completed scan_id=%s status=%s", scan_id, scan.status)
    return scan


@router.get("/scans/{scan_id}/report", response_model=ScanReportResponse)
def read_scan_report(scan_id: str) -> ScanReportResponse:
    logger.info("read scan report requested scan_id=%s", scan_id)
    try:
        report = get_scan_report(scan_id)
    except LookupError as exc:
        logger.warning("read scan report not found scan_id=%s", scan_id)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        logger.exception("read scan report database error scan_id=%s", scan_id)
        raise HTTPException(status_code=500, detail="Failed to build scan report") from exc

    logger.info("read scan report completed scan_id=%s finding_count=%d", scan_id, _report_finding_count(report))
    return report


@router.get("/scans/{scan_id}/report/enriched", response_model=EnrichedReportResponse)
def read_enriched_scan_report(scan_id: str) -> EnrichedReportResponse:
    logger.info("read enriched scan report requested scan_id=%s", scan_id)
    try:
        report = run_or_wait_scan_workflow(scan_id)["final_report"]
    except LookupError as exc:
        logger.warning("read enriched scan report not found scan_id=%s", scan_id)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        logger.exception("read enriched scan report database error scan_id=%s", scan_id)
        raise HTTPException(status_code=500, detail="Failed to build enriched scan report") from exc

    logger.info("read enriched scan report completed scan_id=%s finding_count=%d", scan_id, _report_finding_count(report))
    return report


@router.get("/scans/{scan_id}/events")
def stream_scan_events(scan_id: str) -> StreamingResponse:
    logger.info("SSE subscription opened scan_id=%s", scan_id)
    subscriber_queue, backlog = subscribe(scan_id)

    def event_generator():
        try:
            for event in backlog:
                yield format_sse_data(event)

            while True:
                try:
                    item = subscriber_queue.get(timeout=30)
                except Empty:
                    continue

                if not hasattr(item, "model_dump"):
                    break

                yield format_sse_data(item)
        finally:
            unsubscribe(scan_id, subscriber_queue)
            logger.info("SSE subscription closed scan_id=%s", scan_id)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )


def _report_finding_count(report: ScanReportResponse | EnrichedReportResponse) -> int:
    return sum(category.count for category in report.categories)
