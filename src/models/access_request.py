"""Access Request models for IAM governance"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class RequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    EMERGENCY_APPROVED = "emergency_approved"


class AccessLevel(str, Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    EXECUTE = "execute"


class RequestType(str, Enum):
    NEW_ACCESS = "new_access"
    MODIFY_ACCESS = "modify_access"
    REMOVE_ACCESS = "remove_access"
    EMERGENCY_ACCESS = "emergency_access"
    TEMPORARY_ACCESS = "temporary_access"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessRequest(BaseModel):
    """Core access request model"""
    id: str
    user_id: str
    system_id: str
    access_level: AccessLevel
    request_type: RequestType = RequestType.NEW_ACCESS
    justification: str
    
    # Request metadata
    requested_by: str
    requested_date: datetime = Field(default_factory=datetime.now)
    required_by_date: Optional[datetime] = None
    is_emergency: bool = False
    
    # Status and workflow
    status: RequestStatus = RequestStatus.PENDING
    risk_score: Optional[int] = Field(None, ge=1, le=100)
    risk_level: Optional[RiskLevel] = None
    
    # Decision information
    approved_by: Optional[str] = None
    approved_date: Optional[datetime] = None
    denied_by: Optional[str] = None
    denied_date: Optional[datetime] = None
    denial_reason: Optional[str] = None
    
    # Temporary access
    temporary_until: Optional[datetime] = None
    
    # Audit trail
    decision_history: List[Dict[str, Any]] = Field(default_factory=list)
    policy_violations: List[str] = Field(default_factory=list)
    regulatory_flags: List[str] = Field(default_factory=list)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class DecisionContext(BaseModel):
    """Context information for access decisions"""
    request: AccessRequest
    user_context: Dict[str, Any]
    system_context: Dict[str, Any]
    policy_analysis: Dict[str, Any]
    risk_analysis: Dict[str, Any]
    regulatory_analysis: Dict[str, Any]
    sod_analysis: Dict[str, Any]
    
    # Decision outputs
    recommendation: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    escalation_required: bool = False
    conditions: List[str] = Field(default_factory=list)
    monitoring_requirements: List[str] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """Comprehensive audit record for governance"""
    request_id: str
    timestamp: datetime = Field(default_factory=datetime.now)
    agent_name: str
    action: str
    decision: str
    reasoning: str
    confidence_score: Optional[float] = None
    policies_evaluated: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    regulatory_considerations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }