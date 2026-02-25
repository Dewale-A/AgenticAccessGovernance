"""User, Role, and Department models for IAM governance"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum


class UserStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TERMINATED = "terminated"


class Department(str, Enum):
    RETAIL_BANKING = "Retail Banking"
    RISK_MANAGEMENT = "Risk Management"
    COMPLIANCE = "Compliance"
    IT_ENGINEERING = "IT/Engineering"
    TREASURY = "Treasury"


class Role(BaseModel):
    """Role model for RBAC"""
    id: str
    name: str
    department: Department
    permissions: List[str]
    sensitivity_tier_access: List[str]  # Internal, Confidential, Restricted
    description: Optional[str] = None


class User(BaseModel):
    """User model with comprehensive IAM attributes"""
    id: str
    name: str
    email: EmailStr
    department: Department
    role: str
    title: str
    hire_date: datetime
    last_certification_date: Optional[datetime] = None
    manager_id: Optional[str] = None
    status: UserStatus = UserStatus.ACTIVE
    
    # Training certifications
    privacy_training_date: Optional[datetime] = None
    model_risk_training_date: Optional[datetime] = None
    background_check_date: Optional[datetime] = None
    sox_certification_date: Optional[datetime] = None
    
    # Risk attributes
    risk_score: int = Field(default=50, ge=1, le=100)
    failed_access_attempts: int = 0
    last_login: Optional[datetime] = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class UserContext(BaseModel):
    """Extended user context for access decisions"""
    user: User
    current_entitlements: List[str]
    recent_access_history: List[dict]
    manager_info: Optional[User] = None
    certification_status: dict
    anomaly_flags: List[str] = []