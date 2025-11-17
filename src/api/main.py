"""
FastAPI Main Application
REST API for DevSecOps Pipeline Guardian
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging

from src.orchestrator.security_orchestrator import SecurityOrchestrator, ScanType
from src.api.dependencies import get_orchestrator, get_config
from src.monitoring.metrics import get_metrics_collector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="DevSecOps Pipeline Guardian API",
    description="Security scanning orchestration and policy enforcement platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class ScanRequest(BaseModel):
    """Scan request model"""
    scan_type: str
    target: str
    options: Optional[Dict] = {}


class ScanResponse(BaseModel):
    """Scan response model"""
    scan_id: str
    status: str
    message: str


class ScanResultResponse(BaseModel):
    """Scan result response model"""
    scan_id: str
    scan_type: str
    target: str
    status: str
    results: Optional[Dict] = None
    policy_evaluation: Optional[Dict] = None


# Health check endpoint
@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "DevSecOps Pipeline Guardian"}


# Prometheus metrics endpoint
@app.get("/metrics", tags=["Monitoring"])
async def prometheus_metrics():
    """
    Prometheus metrics endpoint

    Returns:
        Prometheus-formatted metrics
    """
    from fastapi.responses import Response

    metrics_collector = get_metrics_collector()
    metrics_data = metrics_collector.get_metrics()

    return Response(
        content=metrics_data,
        media_type=metrics_collector.get_content_type()
    )


# Scan endpoints
@app.post("/api/v1/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator)
):
    """
    Create and initiate a new security scan
    
    Args:
        scan_request: Scan configuration
        background_tasks: FastAPI background tasks
        orchestrator: SecurityOrchestrator instance
        
    Returns:
        Scan response with scan_id
    """
    try:
        # Map scan type string to ScanType enum
        scan_type_map = {
            'full': ScanType.FULL,
            'sast': ScanType.SAST,
            'dast': ScanType.DAST,
            'dependency': ScanType.DEPENDENCY,
            'container': ScanType.CONTAINER
        }
        
        scan_type = scan_type_map.get(scan_request.scan_type.lower())
        if not scan_type:
            raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_request.scan_type}")
        
        # Start scan in background
        scan_id = orchestrator._generate_scan_id()
        
        async def run_scan_task():
            try:
                await orchestrator.run_scan(scan_type, scan_request.target, scan_request.options)
            except Exception as e:
                logger.error(f"Scan {scan_id} failed: {str(e)}")
        
        background_tasks.add_task(run_scan_task)
        
        return ScanResponse(
            scan_id=scan_id,
            status="pending",
            message=f"{scan_request.scan_type} scan initiated"
        )
        
    except Exception as e:
        logger.error(f"Failed to create scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResultResponse, tags=["Scans"])
async def get_scan_result(
    scan_id: str,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator)
):
    """
    Get scan results by scan ID
    
    Args:
        scan_id: Unique scan identifier
        orchestrator: SecurityOrchestrator instance
        
    Returns:
        Scan results
    """
    results = orchestrator.get_scan_results(scan_id)
    
    if not results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return ScanResultResponse(**results)


@app.get("/api/v1/scans/{scan_id}/status", tags=["Scans"])
async def get_scan_status(
    scan_id: str,
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator)
):
    """
    Get scan status by scan ID
    
    Args:
        scan_id: Unique scan identifier
        orchestrator: SecurityOrchestrator instance
        
    Returns:
        Scan status
    """
    status = orchestrator.get_scan_status(scan_id)
    
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    
    return {"scan_id": scan_id, "status": status.value}


@app.get("/api/v1/scans", tags=["Scans"])
async def list_scans(
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator)
):
    """
    List all scans
    
    Args:
        orchestrator: SecurityOrchestrator instance
        
    Returns:
        List of all scans
    """
    scans = orchestrator.list_scans()
    return {"scans": scans, "total": len(scans)}


@app.get("/api/v1/scans/{scan_id}/export", tags=["Scans"])
async def export_scan_results(
    scan_id: str,
    format: str = "json",
    orchestrator: SecurityOrchestrator = Depends(get_orchestrator)
):
    """
    Export scan results in specified format
    
    Args:
        scan_id: Unique scan identifier
        format: Export format (json, sarif, html)
        orchestrator: SecurityOrchestrator instance
        
    Returns:
        Exported scan results
    """
    try:
        exported = orchestrator.export_results(scan_id, format)
        
        # Set appropriate content type
        content_types = {
            'json': 'application/json',
            'sarif': 'application/sarif+json',
            'html': 'text/html'
        }
        
        from fastapi.responses import Response
        return Response(
            content=exported,
            media_type=content_types.get(format, 'text/plain')
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Policy endpoints
@app.get("/api/v1/policy/status", tags=["Policy"])
async def get_policy_status(config: Dict = Depends(get_config)):
    """Get policy enforcement status"""
    policy_config = config.get('policy', {})
    return {
        "enabled": policy_config.get('enabled', False),
        "opa_url": policy_config.get('opa_url', 'N/A'),
        "policy_package": policy_config.get('policy_package', 'N/A')
    }


# Metrics endpoint
@app.get("/api/v1/metrics", tags=["Metrics"])
async def get_metrics(orchestrator: SecurityOrchestrator = Depends(get_orchestrator)):
    """Get platform metrics"""
    scans = orchestrator.list_scans()
    
    completed_scans = [s for s in scans if s['status'] == 'completed']
    failed_scans = [s for s in scans if s['status'] == 'failed']
    running_scans = [s for s in scans if s['status'] == 'running']
    
    return {
        "total_scans": len(scans),
        "completed_scans": len(completed_scans),
        "failed_scans": len(failed_scans),
        "running_scans": len(running_scans)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
