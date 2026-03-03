"""Risk Scorer Tool - Assigns risk scores to access requests based on multiple factors"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path


logger = logging.getLogger(__name__)


def score_access_risk(request_data: Dict[str, Any], user_data: Dict[str, Any], 
                     system_data: Dict[str, Any], policy_analysis: Dict[str, Any],
                     sod_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate comprehensive risk score for access request based on multiple factors.
    
    Args:
        request_data: Access request information
        user_data: User profile and context
        system_data: Target system information
        policy_analysis: Results from policy checker
        sod_analysis: Results from SoD validator
        
    Returns:
        Risk scoring results with detailed breakdown
    """
    try:
        # Initialize risk components
        risk_components = {
            "user_risk": 0,
            "system_risk": 0, 
            "access_level_risk": 0,
            "policy_risk": 0,
            "sod_risk": 0,
            "temporal_risk": 0,
            "anomaly_risk": 0
        }
        
        risk_factors = []
        
        # Calculate user-based risk
        user_risk = _calculate_user_risk(user_data, risk_factors)
        risk_components["user_risk"] = user_risk
        
        # Calculate system-based risk
        system_risk = _calculate_system_risk(system_data, risk_factors)
        risk_components["system_risk"] = system_risk
        
        # Calculate access level risk
        access_risk = _calculate_access_level_risk(request_data, system_data, risk_factors)
        risk_components["access_level_risk"] = access_risk
        
        # Calculate policy-based risk
        policy_risk = _calculate_policy_risk(policy_analysis, risk_factors)
        risk_components["policy_risk"] = policy_risk
        
        # Calculate SoD-based risk
        sod_risk = _calculate_sod_risk(sod_analysis, risk_factors)
        risk_components["sod_risk"] = sod_risk
        
        # Calculate temporal risk
        temporal_risk = _calculate_temporal_risk(request_data, user_data, risk_factors)
        risk_components["temporal_risk"] = temporal_risk
        
        # Calculate anomaly risk
        anomaly_risk = _calculate_anomaly_risk(request_data, user_data, risk_factors)
        risk_components["anomaly_risk"] = anomaly_risk
        
        # Calculate overall risk score (weighted combination)
        weights = {
            "user_risk": 0.15,
            "system_risk": 0.25,
            "access_level_risk": 0.20,
            "policy_risk": 0.15,
            "sod_risk": 0.15,
            "temporal_risk": 0.05,
            "anomaly_risk": 0.05
        }
        
        overall_score = sum(risk_components[component] * weights[component] 
                          for component in risk_components)
        
        # Ensure score is within bounds
        overall_score = max(1, min(100, int(overall_score)))
        
        # Determine risk level
        risk_level = _determine_risk_level(overall_score)
        
        # Generate recommendations
        recommendations = _generate_recommendations(overall_score, risk_components, risk_factors)
        
        return {
            "overall_risk_score": overall_score,
            "risk_level": risk_level,
            "risk_components": risk_components,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "monitoring_requirements": _get_monitoring_requirements(overall_score, risk_factors),
            "approval_requirements": _get_approval_requirements(overall_score, risk_level)
        }
        
    except Exception as e:
        logger.error(f"Risk scoring failed: {str(e)}")
        return {
            "overall_risk_score": 100,
            "risk_level": "CRITICAL",
            "error": f"Risk scoring error: {str(e)}",
            "risk_factors": ["System error during risk assessment"],
            "recommendations": ["DENY - Unable to assess risk"]
        }


def _calculate_user_risk(user_data: Dict[str, Any], risk_factors: List[str]) -> int:
    """Calculate user-based risk score"""
    user_score = 20  # Base score
    
    # Check user status
    if user_data.get("status") == "suspended":
        user_score += 50
        risk_factors.append("User account suspended")
    elif user_data.get("status") == "terminated":
        user_score += 80
        risk_factors.append("User account terminated")
    
    # Check tenure (new employees are higher risk)
    hire_date = user_data.get("hire_date")
    if hire_date:
        hire_datetime = datetime.fromisoformat(hire_date.replace("Z", "+00:00"))
        tenure_days = (datetime.now() - hire_datetime).days
        
        if tenure_days < 90:  # Less than 3 months
            user_score += 15
            risk_factors.append("New employee (less than 3 months tenure)")
        elif tenure_days < 365:  # Less than 1 year
            user_score += 5
            risk_factors.append("Recent hire (less than 1 year tenure)")
    
    # Check failed access attempts
    failed_attempts = user_data.get("failed_access_attempts", 0)
    if failed_attempts > 5:
        user_score += 20
        risk_factors.append(f"High failed access attempts: {failed_attempts}")
    elif failed_attempts > 0:
        user_score += 5
        risk_factors.append(f"Recent failed access attempts: {failed_attempts}")
    
    # Check last login (dormant accounts are risky)
    last_login = user_data.get("last_login")
    if last_login:
        last_login_date = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
        days_since_login = (datetime.now() - last_login_date).days
        
        if days_since_login > 90:
            user_score += 25
            risk_factors.append(f"Dormant account - last login {days_since_login} days ago")
        elif days_since_login > 30:
            user_score += 10
            risk_factors.append(f"Infrequent user - last login {days_since_login} days ago")
    
    return min(user_score, 100)


def _calculate_system_risk(system_data: Dict[str, Any], risk_factors: List[str]) -> int:
    """Calculate system-based risk score"""
    base_score = system_data.get("data_sensitivity_score", 50)
    
    # Adjust based on sensitivity tier
    sensitivity_tier = system_data.get("sensitivity_tier")
    if sensitivity_tier == "Restricted":
        base_score += 20
        risk_factors.append("Restricted sensitivity tier system")
    elif sensitivity_tier == "Confidential":
        base_score += 10
        risk_factors.append("Confidential sensitivity tier system")
    
    # Adjust based on regulatory impact
    regulatory_impact = system_data.get("regulatory_impact")
    if regulatory_impact == "HIGH":
        base_score += 15
        risk_factors.append("High regulatory impact system")
    elif regulatory_impact == "MEDIUM":
        base_score += 5
        risk_factors.append("Medium regulatory impact system")
    
    # Check for specific high-risk systems
    high_risk_systems = ["SYS001", "SYS002", "SYS004", "SYS009"]  # Core banking, Risk models, Trading, Settlement
    if system_data.get("id") in high_risk_systems:
        base_score += 10
        risk_factors.append("Critical business system")
    
    return min(base_score, 100)


def _calculate_access_level_risk(request_data: Dict[str, Any], system_data: Dict[str, Any], 
                               risk_factors: List[str]) -> int:
    """Calculate access level based risk score"""
    access_level = request_data.get("access_level")
    base_score = 10
    
    # Risk increases with access level
    if access_level == "read":
        base_score += 10
    elif access_level == "write":
        base_score += 25
        risk_factors.append("Write access requested")
    elif access_level == "admin":
        base_score += 40
        risk_factors.append("Administrative access requested")
    elif access_level == "execute":
        base_score += 35
        risk_factors.append("Execute access requested")
    
    # Higher risk for sensitive systems with elevated access
    if (system_data.get("sensitivity_tier") == "Restricted" and 
        access_level in ["write", "admin", "execute"]):
        base_score += 15
        risk_factors.append("Elevated access to restricted system")
    
    return min(base_score, 100)


def _calculate_policy_risk(policy_analysis: Dict[str, Any], risk_factors: List[str]) -> int:
    """Calculate policy compliance based risk score"""
    base_score = 10
    
    # Check overall policy decision
    decision = policy_analysis.get("overall_decision")
    if decision == "deny":
        base_score += 70
        risk_factors.append("Policy violation - access denied")
    elif decision == "escalate":
        base_score += 30
        risk_factors.append("Policy requires escalation")
    
    # Check violation reasons
    violations = policy_analysis.get("violation_reasons", [])
    base_score += len(violations) * 10
    
    # Check regulatory flags
    regulatory_flags = policy_analysis.get("regulatory_flags", [])
    if regulatory_flags:
        base_score += 20
        risk_factors.append(f"Regulatory compliance issues: {', '.join(regulatory_flags)}")
    
    # Inverse confidence score adds risk
    confidence = policy_analysis.get("confidence_score", 1.0)
    base_score += int((1.0 - confidence) * 20)
    
    return min(base_score, 100)


def _calculate_sod_risk(sod_analysis: Dict[str, Any], risk_factors: List[str]) -> int:
    """Calculate SoD violation based risk score"""
    base_score = 0
    
    if sod_analysis.get("is_blocked"):
        base_score += 80
        risk_factors.append("Blocked by Segregation of Duties violation")
    
    sod_risk_level = sod_analysis.get("risk_level", "LOW")
    if sod_risk_level == "HIGH":
        base_score += 60
    elif sod_risk_level == "MEDIUM":
        base_score += 30
    elif sod_risk_level == "LOW":
        base_score += 5
    
    violations = sod_analysis.get("sod_violations", [])
    warnings = sod_analysis.get("sod_warnings", [])
    
    base_score += len(violations) * 25
    base_score += len(warnings) * 10
    
    if violations:
        risk_factors.append(f"SoD violations: {len(violations)}")
    if warnings:
        risk_factors.append(f"SoD warnings: {len(warnings)}")
    
    return min(base_score, 100)


def _calculate_temporal_risk(request_data: Dict[str, Any], user_data: Dict[str, Any], 
                           risk_factors: List[str]) -> int:
    """Calculate temporal/timing based risk score"""
    base_score = 5
    
    # Emergency requests have higher risk
    if request_data.get("is_emergency"):
        base_score += 25
        risk_factors.append("Emergency access request")
    
    # Check if request is outside business hours
    current_hour = datetime.now().hour
    if current_hour < 8 or current_hour > 18:  # Outside 8 AM - 6 PM
        base_score += 10
        risk_factors.append("Request submitted outside business hours")
    
    # Check required by date urgency
    required_by = request_data.get("required_by_date")
    if required_by:
        required_date = datetime.fromisoformat(required_by.replace("Z", "+00:00"))
        time_diff = (required_date - datetime.now()).days
        
        if time_diff < 1:  # Less than 1 day
            base_score += 15
            risk_factors.append("Urgent request - required within 24 hours")
        elif time_diff < 3:  # Less than 3 days
            base_score += 5
            risk_factors.append("Time-sensitive request")
    
    return min(base_score, 100)


def _calculate_anomaly_risk(request_data: Dict[str, Any], user_data: Dict[str, Any], 
                          risk_factors: List[str]) -> int:
    """Calculate anomaly detection based risk score"""
    base_score = 0
    
    # Check for unusual patterns (simplified for demo)
    user_dept = user_data.get("department")
    
    # Cross-department access requests
    if request_data.get("system_id") in ["SYS003", "SYS007"]:  # Customer Data, HR System
        if user_dept not in ["IT/Engineering"]:
            base_score += 20
            risk_factors.append("Cross-department system access request")
    
    # Role vs system mismatch detection
    user_role = user_data.get("role")
    system_id = request_data.get("system_id")
    
    unusual_combinations = {
        "teller": ["SYS002", "SYS004", "SYS006"],  # Risk models, Trading, ML Registry
        "customer_advisor": ["SYS004", "SYS009"],  # Trading, Settlement
        "software_developer": ["SYS001", "SYS004"]  # Core Banking, Trading
    }
    
    if user_role in unusual_combinations and system_id in unusual_combinations[user_role]:
        base_score += 15
        risk_factors.append(f"Unusual access pattern for role {user_role}")
    
    return min(base_score, 100)


def _determine_risk_level(score: int) -> str:
    """Determine risk level based on score"""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_recommendations(score: int, components: Dict[str, int], 
                            factors: List[str]) -> List[str]:
    """Generate risk-based recommendations"""
    recommendations = []
    
    if score >= 80:
        recommendations.extend([
            "DENY - Critical risk level detected",
            "Require comprehensive risk assessment",
            "Consider alternative access methods or role restructuring"
        ])
    elif score >= 60:
        recommendations.extend([
            "ESCALATE - High risk requires senior management approval",
            "Implement additional controls and monitoring",
            "Require business justification and time limits"
        ])
    elif score >= 40:
        recommendations.extend([
            "CONDITIONAL APPROVAL - Medium risk with conditions",
            "Require manager approval and enhanced logging",
            "Consider temporary access with regular review"
        ])
    else:
        recommendations.extend([
            "APPROVE - Low risk within acceptable parameters",
            "Standard monitoring and audit trail sufficient"
        ])
    
    # Add specific recommendations based on highest risk components
    max_component = max(components.items(), key=lambda x: x[1])
    
    if max_component[0] == "sod_risk" and max_component[1] > 50:
        recommendations.append("Implement compensating controls for SoD conflicts")
    elif max_component[0] == "system_risk" and max_component[1] > 70:
        recommendations.append("Enhanced background checks for high-sensitivity systems")
    elif max_component[0] == "user_risk" and max_component[1] > 60:
        recommendations.append("Additional user verification and training required")
    
    return recommendations


def _get_monitoring_requirements(score: int, factors: List[str]) -> List[str]:
    """Get monitoring requirements based on risk score"""
    requirements = ["Standard audit logging"]
    
    if score >= 60:
        requirements.extend([
            "Real-time access monitoring",
            "Anomaly detection alerts",
            "Monthly access reviews"
        ])
    elif score >= 40:
        requirements.extend([
            "Enhanced logging",
            "Quarterly access reviews"
        ])
    
    if "Emergency access request" in factors:
        requirements.append("Immediate post-access review required")
    
    if any("SoD" in factor for factor in factors):
        requirements.append("Segregation of duties monitoring")
    
    return requirements


def _get_approval_requirements(score: int, risk_level: str) -> Dict[str, Any]:
    """Get approval requirements based on risk assessment"""
    if score >= 80:
        return {
            "approval_level": "CISO",
            "additional_approvers": ["Compliance Director", "Business Unit Head"],
            "documentation_required": ["Risk assessment", "Business justification", "Mitigation plan"]
        }
    elif score >= 60:
        return {
            "approval_level": "Senior Manager",
            "additional_approvers": ["Compliance Officer"],
            "documentation_required": ["Business justification", "Risk acknowledgment"]
        }
    elif score >= 40:
        return {
            "approval_level": "Direct Manager",
            "additional_approvers": [],
            "documentation_required": ["Business justification"]
        }
    else:
        return {
            "approval_level": "Automated",
            "additional_approvers": [],
            "documentation_required": ["Standard request form"]
        }