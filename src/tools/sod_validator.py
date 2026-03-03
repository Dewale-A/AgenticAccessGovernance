"""Segregation of Duties (SoD) Validator Tool - Checks for conflicting access combinations"""

import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

from crewai_tools import tool

logger = logging.getLogger(__name__)


@tool
def validate_segregation_of_duties(request_data: Dict[str, Any], user_data: Dict[str, Any], 
                                 current_entitlements: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate access request against Segregation of Duties rules to prevent conflicts of interest.
    
    Args:
        request_data: Access request information
        user_data: User profile and context
        current_entitlements: User's current system access
        
    Returns:
        SoD validation results with conflict analysis
    """
    try:
        # Load policy data
        policies_path = Path("data/policies.json")
        with open(policies_path, "r") as f:
            policies = json.load(f)
            
        user_id = request_data.get("user_id")
        requested_system = request_data.get("system_id")
        user_role = user_data.get("role")
        
        sod_violations = []
        sod_warnings = []
        risk_level = "LOW"
        
        # Check each SoD rule
        for sod_rule in policies["sod_rules"]:
            violation = _check_sod_rule(sod_rule, requested_system, user_role, current_entitlements)
            
            if violation:
                if sod_rule["severity"] == "HIGH":
                    sod_violations.append(violation)
                    risk_level = "HIGH"
                else:
                    sod_warnings.append(violation)
                    if risk_level == "LOW":
                        risk_level = "MEDIUM"
        
        # Determine overall result
        is_blocked = len(sod_violations) > 0
        recommendation = _get_recommendation(sod_violations, sod_warnings, policies["sod_rules"])
        
        return {
            "is_blocked": is_blocked,
            "risk_level": risk_level,
            "sod_violations": sod_violations,
            "sod_warnings": sod_warnings,
            "recommendation": recommendation,
            "mitigation_options": _get_mitigation_options(sod_violations, policies["sod_rules"]),
            "audit_requirements": _get_audit_requirements(sod_violations, sod_warnings)
        }
        
    except Exception as e:
        logger.error(f"SoD validation failed: {str(e)}")
        return {
            "is_blocked": True,
            "risk_level": "HIGH",
            "error": f"SoD validation error: {str(e)}",
            "sod_violations": ["System error during SoD validation"],
            "recommendation": "DENY - Unable to validate segregation of duties"
        }


def _check_sod_rule(sod_rule: Dict[str, Any], requested_system: str, user_role: str,
                   current_entitlements: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Check a specific SoD rule for violations"""
    
    conflicting_systems = sod_rule["conflicting_systems"]
    conflicting_roles = sod_rule.get("conflicting_roles", [])
    
    # Check if requested system is in conflicting systems
    if requested_system not in conflicting_systems:
        return None
        
    # Check if user role is specifically restricted
    if conflicting_roles and user_role in conflicting_roles:
        return {
            "rule_id": sod_rule["id"],
            "rule_name": sod_rule["name"],
            "violation_type": "ROLE_CONFLICT",
            "description": f"Role {user_role} cannot access systems in this SoD rule",
            "severity": sod_rule["severity"],
            "conflicting_systems": conflicting_systems,
            "current_access": []
        }
    
    # Check for conflicting system access
    user_systems = [ent["system_id"] for ent in current_entitlements if ent["is_active"]]
    conflicts = []
    
    for system in conflicting_systems:
        if system != requested_system and system in user_systems:
            conflicts.append(system)
    
    if conflicts:
        return {
            "rule_id": sod_rule["id"],
            "rule_name": sod_rule["name"],
            "violation_type": "SYSTEM_CONFLICT",
            "description": sod_rule["description"],
            "severity": sod_rule["severity"],
            "requested_system": requested_system,
            "conflicting_systems": conflicts,
            "current_access": [ent for ent in current_entitlements 
                             if ent["system_id"] in conflicts and ent["is_active"]]
        }
    
    return None


def _get_recommendation(violations: List[Dict], warnings: List[Dict], sod_rules: List[Dict]) -> str:
    """Generate recommendation based on SoD analysis"""
    
    if not violations and not warnings:
        return "APPROVE - No segregation of duties conflicts detected"
    
    if violations:
        # Check if any violations allow exceptions
        exceptions_possible = []
        for violation in violations:
            rule = next((r for r in sod_rules if r["id"] == violation["rule_id"]), None)
            if rule and rule.get("exceptions_allowed", False):
                exceptions_possible.append(rule["id"])
        
        if exceptions_possible:
            return "CONDITIONAL_APPROVE - SoD violations detected but exceptions may be granted with proper controls"
        else:
            return "DENY - High-severity SoD violations with no exceptions allowed"
    
    if warnings:
        return "ESCALATE - Medium-risk SoD conflicts require management review"
    
    return "APPROVE"


def _get_mitigation_options(violations: List[Dict], sod_rules: List[Dict]) -> List[str]:
    """Get available mitigation options for SoD violations"""
    options = []
    
    for violation in violations:
        rule = next((r for r in sod_rules if r["id"] == violation["rule_id"]), None)
        if rule:
            if rule.get("exceptions_allowed", False):
                exception_conditions = rule.get("exception_conditions", [])
                for condition in exception_conditions:
                    if condition == "manager_approval":
                        options.append("Require manager approval with business justification")
                    elif condition == "dual_control":
                        options.append("Implement dual control mechanism")
                    elif condition == "senior_manager_approval":
                        options.append("Require senior management approval")
                    elif condition == "time_limited":
                        options.append("Grant temporary access with expiration")
                    elif condition == "enhanced_monitoring":
                        options.append("Enhanced monitoring and audit logging")
    
    if not options:
        options.append("No mitigation options available - consider role separation or workflow redesign")
    
    return list(set(options))  # Remove duplicates


def _get_audit_requirements(violations: List[Dict], warnings: List[Dict]) -> List[str]:
    """Determine audit requirements based on SoD analysis"""
    requirements = []
    
    if violations:
        requirements.extend([
            "Log all access activities with full audit trail",
            "Implement real-time monitoring for conflicting access patterns",
            "Require periodic access reviews by independent party",
            "Document business justification for SoD exception"
        ])
    
    if warnings:
        requirements.extend([
            "Enhanced logging for medium-risk SoD scenarios",
            "Monthly access review by direct manager"
        ])
    
    if violations or warnings:
        requirements.append("Notify compliance team of SoD risk scenario")
    
    return list(set(requirements))  # Remove duplicates


def _analyze_access_patterns(user_entitlements: List[Dict], systems_data: List[Dict]) -> Dict[str, Any]:
    """Analyze user's access patterns for additional SoD insights"""
    
    sensitive_systems = []
    department_systems = {}
    
    for entitlement in user_entitlements:
        if not entitlement["is_active"]:
            continue
            
        system_id = entitlement["system_id"]
        system_info = next((s for s in systems_data if s["id"] == system_id), None)
        
        if system_info:
            # Track sensitive system access
            if system_info["sensitivity_tier"] in ["Restricted", "Confidential"]:
                sensitive_systems.append({
                    "system_id": system_id,
                    "sensitivity": system_info["sensitivity_tier"],
                    "access_level": entitlement["access_level"]
                })
            
            # Track cross-department access
            owner_dept = system_info["owner_department"]
            if owner_dept not in department_systems:
                department_systems[owner_dept] = []
            department_systems[owner_dept].append(system_id)
    
    return {
        "sensitive_system_count": len(sensitive_systems),
        "cross_department_access": len(department_systems) > 1,
        "department_distribution": department_systems,
        "risk_indicators": _identify_risk_indicators(sensitive_systems, department_systems)
    }


def _identify_risk_indicators(sensitive_systems: List[Dict], department_systems: Dict) -> List[str]:
    """Identify potential risk indicators from access patterns"""
    indicators = []
    
    if len(sensitive_systems) > 3:
        indicators.append("High number of sensitive system access")
    
    if len(department_systems) > 2:
        indicators.append("Extensive cross-department access")
    
    # Check for specific high-risk combinations
    system_ids = [s["system_id"] for s in sensitive_systems]
    
    if "SYS004" in system_ids and "SYS009" in system_ids:  # Trading + Settlement
        indicators.append("Trading and settlement system access combination")
    
    if "SYS002" in system_ids and "SYS010" in system_ids:  # Model dev + validation
        indicators.append("Model development and validation access combination")
    
    return indicators