"""
FastAPI REST API for AgenticAccessGovernance System
Provides 8 endpoints for access request processing and management.
"""

import json
import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from src.crew import governance_crew
from src.models.access_request import AccessRequest, RequestStatus
from src.models.user import User
from src.db.iam_database import IAMDatabase
from src.config.settings import settings

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app initialization
app = FastAPI(
    title="AgenticAccessGovernance API",
    description="AI-powered Identity and Access Management governance system for financial services",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global database instance
db: Optional[IAMDatabase] = None

# Pydantic models for API requests/responses
class AccessRequestCreate(BaseModel):
    """Request model for creating new access requests."""
    user_id: str = Field(..., description="Unique identifier for the user")
    system_id: str = Field(..., description="Unique identifier for the target system")
    access_level: str = Field(..., description="Requested access level (read/write/admin/execute)")
    request_type: str = Field(default="new_access", description="Type of access request")
    justification: str = Field(..., description="Business justification for the access")
    required_by_date: Optional[datetime] = Field(None, description="Date by which access is required")
    is_emergency: bool = Field(default=False, description="Whether this is an emergency request")

class AccessRequestResponse(BaseModel):
    """Response model for access requests."""
    request_id: str
    status: str
    message: str
    decision: Optional[str] = None
    processing_time: Optional[float] = None

class AsyncRequestResponse(BaseModel):
    """Response model for async request processing."""
    request_id: str
    status: str
    message: str
    tracking_url: str

class HealthResponse(BaseModel):
    """Response model for health check."""
    status: str
    timestamp: datetime
    version: str
    database_connected: bool
    agents_initialized: bool

class UserEntitlementsResponse(BaseModel):
    """Response model for user entitlements."""
    user_id: str
    entitlements: List[Dict[str, Any]]
    total_count: int

class AuditTrailResponse(BaseModel):
    """Response model for audit trail."""
    request_id: str
    audit_records: List[Dict[str, Any]]
    total_records: int

class CertificationReviewRequest(BaseModel):
    """Request model for certification review."""
    user_id: str = Field(..., description="User ID to review")
    review_type: str = Field(default="full", description="Type of review (full/quick/specific)")

class CertificationReviewResponse(BaseModel):
    """Response model for certification review."""
    user_id: str
    review_status: str
    certification_summary: Dict[str, Any]
    recommendations: List[str]

# Background task storage (in production, use Redis or similar)
background_tasks = {}

@app.on_event("startup")
async def startup_event():
    """Initialize the application on startup."""
    global db
    logger.info("Starting AgenticAccessGovernance API")
    
    try:
        # Initialize database
        db = IAMDatabase()
        await db.initialize()
        logger.info("Database initialized successfully")
        
        # Initialize governance crew
        await governance_crew.initialize()
        logger.info("Governance crew initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up on application shutdown."""
    logger.info("Shutting down AgenticAccessGovernance API")
    if db:
        await db.close()

# Dependency to get database instance
async def get_database():
    """Dependency to get database instance."""
    if not db:
        raise HTTPException(status_code=500, detail="Database not initialized")
    return db

# API Endpoints

@app.post("/api/v1/request", response_model=AccessRequestResponse, status_code=status.HTTP_201_CREATED)
async def submit_access_request(
    request: AccessRequestCreate,
    db_instance: IAMDatabase = Depends(get_database)
) -> AccessRequestResponse:
    """
    Submit a new access request for synchronous processing.
    
    Processes the request through the complete governance workflow and returns
    the final decision along with detailed reasoning.
    """
    start_time = datetime.now()
    
    try:
        # Generate unique request ID
        request_id = f"REQ{int(datetime.now().timestamp() * 1000)}"
        
        # Convert to processing format
        request_data = {
            "id": request_id,
            "user_id": request.user_id,
            "system_id": request.system_id,
            "access_level": request.access_level,
            "request_type": request.request_type,
            "justification": request.justification,
            "requested_by": request.user_id,
            "requested_date": datetime.now().isoformat(),
            "required_by_date": request.required_by_date.isoformat() if request.required_by_date else None,
            "is_emergency": request.is_emergency,
            "status": "processing"
        }
        
        logger.info(f"Processing access request {request_id} synchronously")
        
        # Process through governance workflow
        result = await governance_crew.process_access_request(request_data)
        
        # Calculate processing time
        processing_time = (datetime.now() - start_time).total_seconds()
        
        # Determine HTTP status based on decision
        decision = result.get("final_decision", "ERROR")
        http_status = status.HTTP_201_CREATED
        
        if decision == "ERROR":
            http_status = status.HTTP_500_INTERNAL_SERVER_ERROR
        elif decision == "DENIED":
            http_status = status.HTTP_200_OK  # Still a valid response
        
        return AccessRequestResponse(
            request_id=request_id,
            status="completed",
            message=f"Access request processed with decision: {decision}",
            decision=decision,
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Error processing access request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process access request: {str(e)}"
        )

@app.post("/api/v1/request/async", response_model=AsyncRequestResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_async_access_request(
    request: AccessRequestCreate,
    background_tasks: BackgroundTasks,
    db_instance: IAMDatabase = Depends(get_database)
) -> AsyncRequestResponse:
    """
    Submit a new access request for asynchronous processing.
    
    Returns immediately with a request ID that can be used to track
    processing status and retrieve results.
    """
    try:
        # Generate unique request ID
        request_id = f"REQ{int(datetime.now().timestamp() * 1000)}"
        
        # Convert to processing format
        request_data = {
            "id": request_id,
            "user_id": request.user_id,
            "system_id": request.system_id,
            "access_level": request.access_level,
            "request_type": request.request_type,
            "justification": request.justification,
            "requested_by": request.user_id,
            "requested_date": datetime.now().isoformat(),
            "required_by_date": request.required_by_date.isoformat() if request.required_by_date else None,
            "is_emergency": request.is_emergency,
            "status": "submitted"
        }
        
        # Store initial status
        background_tasks_storage = {
            "status": "processing",
            "submitted_at": datetime.now(),
            "request_data": request_data
        }
        background_tasks[request_id] = background_tasks_storage
        
        # Add background task for processing
        background_tasks.add_task(process_request_async, request_id, request_data)
        
        logger.info(f"Access request {request_id} submitted for asynchronous processing")
        
        return AsyncRequestResponse(
            request_id=request_id,
            status="submitted",
            message="Access request submitted for processing",
            tracking_url=f"/api/v1/request/{request_id}"
        )
        
    except Exception as e:
        logger.error(f"Error submitting async access request: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit request for processing: {str(e)}"
        )

async def process_request_async(request_id: str, request_data: Dict[str, Any]):
    """Background task to process access request asynchronously."""
    try:
        logger.info(f"Starting async processing for request {request_id}")
        
        # Update status to processing
        if request_id in background_tasks:
            background_tasks[request_id]["status"] = "processing"
            background_tasks[request_id]["processing_started"] = datetime.now()
        
        # Process through governance workflow
        result = await governance_crew.process_access_request(request_data)
        
        # Update status with results
        if request_id in background_tasks:
            background_tasks[request_id].update({
                "status": "completed",
                "processing_completed": datetime.now(),
                "result": result,
                "decision": result.get("final_decision", "ERROR")
            })
        
        logger.info(f"Async processing completed for request {request_id}")
        
    except Exception as e:
        logger.error(f"Error in async processing for request {request_id}: {str(e)}")
        
        # Update status with error
        if request_id in background_tasks:
            background_tasks[request_id].update({
                "status": "error",
                "error": str(e),
                "processing_completed": datetime.now()
            })

@app.get("/api/v1/request/{request_id}")
async def get_request_status(
    request_id: str,
    db_instance: IAMDatabase = Depends(get_database)
) -> Dict[str, Any]:
    """
    Get the status and decision for a specific access request.
    
    Returns current processing status, decision (if completed), and detailed
    results from the governance workflow.
    """
    try:
        logger.info(f"Getting status for request {request_id}")
        
        # First check background tasks for async requests
        if request_id in background_tasks:
            task_info = background_tasks[request_id]
            
            response = {
                "request_id": request_id,
                "status": task_info["status"],
                "submitted_at": task_info["submitted_at"].isoformat(),
                "request_data": task_info.get("request_data", {})
            }
            
            if "processing_started" in task_info:
                response["processing_started"] = task_info["processing_started"].isoformat()
            
            if "processing_completed" in task_info:
                response["processing_completed"] = task_info["processing_completed"].isoformat()
                
            if "result" in task_info:
                response["governance_result"] = task_info["result"]
                response["decision"] = task_info.get("decision")
                
            if "error" in task_info:
                response["error"] = task_info["error"]
                
            return response
        
        # Check database for completed requests
        db_result = await db_instance.get_request_status(request_id)
        
        if db_result:
            return {
                "request_id": request_id,
                "status": "completed",
                "governance_result": db_result,
                "retrieved_from": "database"
            }
        
        # Request not found
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Access request {request_id} not found"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting request status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve request status: {str(e)}"
        )

@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """
    System health check endpoint.
    
    Returns the current status of the governance system including
    database connectivity and agent initialization status.
    """
    try:
        # Check database connectivity
        database_connected = False
        if db:
            try:
                # Simple database connectivity check
                await db.get_user("health_check")  # This will return None but tests connectivity
                database_connected = True
            except:
                database_connected = False
        
        # Check agent initialization
        agents_initialized = governance_crew.db is not None
        
        overall_status = "healthy" if database_connected and agents_initialized else "degraded"
        
        return HealthResponse(
            status=overall_status,
            timestamp=datetime.now(),
            version="1.0.0",
            database_connected=database_connected,
            agents_initialized=agents_initialized
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return HealthResponse(
            status="unhealthy",
            timestamp=datetime.now(),
            version="1.0.0",
            database_connected=False,
            agents_initialized=False
        )

@app.get("/api/v1/users", response_model=List[Dict[str, Any]])
async def list_users(
    limit: int = 50,
    offset: int = 0,
    db_instance: IAMDatabase = Depends(get_database)
) -> List[Dict[str, Any]]:
    """
    List all users in the system.
    
    Returns a paginated list of users with their basic information
    and current status.
    """
    try:
        logger.info(f"Listing users with limit={limit}, offset={offset}")
        
        users = await db_instance.list_users(limit=limit, offset=offset)
        
        return users
        
    except Exception as e:
        logger.error(f"Error listing users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve users: {str(e)}"
        )

@app.get("/api/v1/users/{user_id}/entitlements", response_model=UserEntitlementsResponse)
async def get_user_entitlements(
    user_id: str,
    db_instance: IAMDatabase = Depends(get_database)
) -> UserEntitlementsResponse:
    """
    Get current entitlements for a specific user.
    
    Returns all active entitlements/access permissions for the user
    across all systems.
    """
    try:
        logger.info(f"Getting entitlements for user {user_id}")
        
        entitlements = await governance_crew.get_user_entitlements(user_id)
        
        if entitlements is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User {user_id} not found"
            )
        
        return UserEntitlementsResponse(
            user_id=user_id,
            entitlements=entitlements,
            total_count=len(entitlements)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user entitlements: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user entitlements: {str(e)}"
        )

@app.get("/api/v1/audit/{request_id}", response_model=AuditTrailResponse)
async def get_audit_trail(
    request_id: str,
    db_instance: IAMDatabase = Depends(get_database)
) -> AuditTrailResponse:
    """
    Get the complete audit trail for a specific access request.
    
    Returns detailed audit records showing all decisions, reasoning,
    and governance workflow steps for the request.
    """
    try:
        logger.info(f"Getting audit trail for request {request_id}")
        
        audit_records = await governance_crew.get_audit_trail(request_id)
        
        if not audit_records:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No audit records found for request {request_id}"
            )
        
        return AuditTrailResponse(
            request_id=request_id,
            audit_records=audit_records,
            total_records=len(audit_records)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audit trail: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve audit trail: {str(e)}"
        )

@app.post("/api/v1/certification/review", response_model=CertificationReviewResponse)
async def trigger_certification_review(
    review_request: CertificationReviewRequest,
    db_instance: IAMDatabase = Depends(get_database)
) -> CertificationReviewResponse:
    """
    Trigger a certification review for a specific user.
    
    Reviews the user's training certifications, regulatory compliance,
    and provides recommendations for any required actions.
    """
    try:
        logger.info(f"Triggering certification review for user {review_request.user_id}")
        
        review_result = await governance_crew.review_certifications(review_request.user_id)
        
        if "error" in review_result:
            if "not found" in review_result["error"].lower():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=review_result["error"]
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=review_result["error"]
                )
        
        # Parse the certification review text to extract structured information
        certification_text = review_result.get("certification_review", "")
        
        # Create a basic certification summary (in production, this would be more sophisticated)
        certification_summary = {
            "review_completed": True,
            "review_date": review_result.get("reviewed_at"),
            "overall_status": "compliant" if "compliant" in certification_text.lower() else "review_required",
            "details": certification_text[:500] + "..." if len(certification_text) > 500 else certification_text
        }
        
        # Extract basic recommendations
        recommendations = []
        if "expired" in certification_text.lower():
            recommendations.append("Review expired certifications")
        if "training" in certification_text.lower():
            recommendations.append("Complete required training")
        if "background" in certification_text.lower():
            recommendations.append("Update background check")
        
        if not recommendations:
            recommendations.append("No immediate actions required")
        
        return CertificationReviewResponse(
            user_id=review_request.user_id,
            review_status="completed",
            certification_summary=certification_summary,
            recommendations=recommendations
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in certification review: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to complete certification review: {str(e)}"
        )

# Additional utility endpoints

@app.get("/api/v1/stats")
async def get_system_stats() -> Dict[str, Any]:
    """Get system statistics and metrics."""
    try:
        # In production, this would query actual metrics
        return {
            "requests_processed_today": len(background_tasks),
            "active_background_tasks": len([t for t in background_tasks.values() if t["status"] == "processing"]),
            "system_uptime": "N/A",  # Would calculate actual uptime
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system statistics"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_debug,
        log_level=settings.log_level.lower()
    )