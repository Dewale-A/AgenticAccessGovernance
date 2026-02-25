"""Policy, SoD Rule, and Regulatory Constraint models"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class SensitivityTier(str, Enum):
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


class RegulatorType(str, Enum):
    OSFI = "OSFI"
    SR_11_7 = "SR 11-7"
    PIPEDA = "PIPEDA"
    IIROC = "IIROC"
    SOX = "SOX"


class PolicyType(str, Enum):
    RBAC = "rbac"
    SOD = "sod"
    REGULATORY = "regulatory"
    DEPARTMENTAL = "departmental"
    SENSITIVITY = "sensitivity"


class ActionType(str, Enum):
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"
    CONDITIONAL = "conditional"


class Policy(BaseModel):
    """Core policy model for access governance"""
    id: str
    name: str
    policy_type: PolicyType
    description: str
    
    # Policy definition
    conditions: Dict[str, Any]
    action: ActionType
    priority: int = Field(default=100, ge=1, le=1000)
    
    # Metadata
    created_date: datetime
    last_modified: datetime
    is_active: bool = True
    regulatory_reference: Optional[str] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class RBACRule(BaseModel):
    """Role-Based Access Control rule"""
    id: str
    role: str
    system: str
    access_levels: List[str]
    conditions: Dict[str, Any] = Field(default_factory=dict)
    exceptions: List[str] = Field(default_factory=list)


class SoDRule(BaseModel):
    """Segregation of Duties rule"""
    id: str
    name: str
    description: str
    conflicting_systems: List[str]
    conflicting_roles: List[str] = Field(default_factory=list)
    severity: str = "HIGH"  # HIGH, MEDIUM, LOW
    exceptions_allowed: bool = False
    exception_conditions: List[str] = Field(default_factory=list)


class RegulatoryConstraint(BaseModel):
    """Regulatory compliance constraint"""
    id: str
    regulator: RegulatorType
    regulation_name: str
    description: str
    
    # Requirements
    applies_to_systems: List[str]
    applies_to_roles: List[str] = Field(default_factory=list)
    certification_required: Optional[str] = None
    certification_validity_days: Optional[int] = None
    
    # Enforcement
    is_mandatory: bool = True
    violation_severity: str = "HIGH"
    audit_frequency: Optional[str] = None


class System(BaseModel):
    """Enterprise system/resource model"""
    id: str
    name: str
    description: str
    sensitivity_tier: SensitivityTier
    data_classification: str
    regulator: Optional[RegulatorType] = None
    owner_department: str
    access_levels: List[str]
    
    # Risk attributes
    data_sensitivity_score: int = Field(ge=1, le=100)
    regulatory_impact: str = "HIGH"  # HIGH, MEDIUM, LOW
    audit_required: bool = True


class Entitlement(BaseModel):
    """Current user entitlement/access mapping"""
    id: str
    user_id: str
    system_id: str
    access_level: str
    granted_date: datetime
    granted_by: str
    expires_date: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class PolicyEvaluation(BaseModel):
    """Result of policy evaluation"""
    policy_id: str
    policy_name: str
    matched: bool
    action: ActionType
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    violated_conditions: List[str] = Field(default_factory=list)
    regulatory_flags: List[str] = Field(default_factory=list)