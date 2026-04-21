from fastapi import APIRouter, HTTPException
import grpc
import psycopg

from graph.workflow import run_enriched_report_graph
from grpc_clients.tool_client import run_baseline_scan
from schemas.scan import EnrichedReportResponse, ScanDetailsResponse, ScanReportResponse, ScanRequest, ScanResponse
from services.reports import get_scan_report
from services.scans import get_scan_details
from services.targets import TargetValidationError, validate_scan_target


router = APIRouter()


@router.post("/scans", response_model=ScanResponse)
def create_scan(request: ScanRequest) -> ScanResponse:
    try:
        target = validate_scan_target(request.target)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        result = run_baseline_scan(target)
    except grpc.RpcError as exc:
        detail = exc.details() or "Failed to call scanner service"
        raise HTTPException(status_code=500, detail=detail) from exc

    return ScanResponse(scan_id=result["scan_id"], status=result["status"])


@router.get("/scans/{scan_id}", response_model=ScanDetailsResponse)
def read_scan(scan_id: str) -> ScanDetailsResponse:
    try:
        scan = get_scan_details(scan_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=500, detail="Failed to fetch scan") from exc

    return scan


@router.get("/scans/{scan_id}/report", response_model=ScanReportResponse)
def read_scan_report(scan_id: str) -> ScanReportResponse:
    try:
        report = get_scan_report(scan_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=500, detail="Failed to build scan report") from exc

    return report


@router.get("/scans/{scan_id}/report/enriched", response_model=EnrichedReportResponse)
def read_enriched_scan_report(scan_id: str) -> EnrichedReportResponse:
    try:
        report = run_enriched_report_graph(scan_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=500, detail="Failed to build enriched scan report") from exc

    return report
