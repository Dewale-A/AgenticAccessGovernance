"""Policy Checker Tool - Validates access requests against RBAC rules and policies"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from crewai_tools import tool
from src.models.policy import PolicyEvaluation, ActionType

logger = logging.getLogger(__name__)


@tool("Policy Checker")
def check_policies(request_data: Dict[str, Any], user_data: Dict[str, Any], system_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Check access request against RBAC rules, sensitivity policies, and departmental policies.
    
    Args:
        request_data: Access request information
        user_data: User profile and context
        system_data: Target system information
        
    Returns:
        Policy evaluation results with matched rules and violations
    """
    try:
        # Load policy data
        policies_path = Path("data/policies.json")
        with open(policies_path, "r") as f:
            policies = json.load(f)
            
        user_role = user_data.get("role")
        user_dept = user_data.get("department")
        system_id = request_data.get("system_id")
        access_level = request_data.get("access_level")
        
        evaluation_results = []
        overall_decision = ActionType.APPROVE
        violation_reasons = []
        regulatory_flags = []
        
        # Check RBAC rules
        rbac_result = _check_rbac_rules(
            policies["rbac_rules"], user_role, system_id, access_level, user_data
        )
        evaluation_results.extend(rbac_result["evaluations"])
        if not rbac_result["allowed"]:
            overall_decision = ActionType.DENY
            violation_reasons.extend(rbac_result["violations"])
            
        # Check sensitivity tier access
        sensitivity_result = _check_sensitivity_rules(
            policies["sensitivity_rules"], user_role, system_data.get("sensitivity_tier"), user_data
        )
        evaluation_results.extend(sensitivity_result["evaluations"])
        if not sensitivity_result["allowed"]:
            overall_decision = ActionType.ESCALATE
            violation_reasons.extend(sensitivity_result["violations"])
            
        # Check departmental policies
        dept_result = _check_departmental_policies(
            policies["department_policies"], user_dept, system_id, request_data
        )
        evaluation_results.extend(dept_result["evaluations"])
        if dept_result["requires_escalation"]:
            overall_decision = ActionType.ESCALATE
            
        # Check regulatory constraints
        regulatory_result = _check_regulatory_constraints(
            policies["regulatory_constraints"], system_id, user_role, user_data
        )
        evaluation_results.extend(regulatory_result["evaluations"])
        regulatory_flags.extend(regulatory_result["flags"])
        if not regulatory_result["compliant"]:
            overall_decision = ActionType.DENY
            violation_reasons.extend(regulatory_result["violations"])
            
        return {
            "overall_decision": overall_decision.value,
            "confidence_score": _calculate_confidence(evaluation_results),
            "policy_evaluations": [eval_result.__dict__ for eval_result in evaluation_results],
            "violation_reasons": violation_reasons,
            "regulatory_flags": regulatory_flags,
            "requires_conditions": dept_result.get("conditions", []),
            "escalation_reason": "Cross-department access or high-risk system" if overall_decision == ActionType.ESCALATE else None
        }
        
    except Exception as e:
        logger.error(f"Policy check failed: {str(e)}")
        return {
            "overall_decision": ActionType.DENY.value,
            "confidence_score": 1.0,
            "error": f"Policy evaluation error: {str(e)}",
            "violation_reasons": ["System error during policy evaluation"]
        }


def _check_rbac_rules(rbac_rules: List[Dict], user_role: str, system_id: str, 
                     access_level: str, user_data: Dict) -> Dict[str, Any]:
    """Check Role-Based Access Control rules"""
    matching_rules = []
    violations = []
    
    for rule in rbac_rules:
        if rule["role"] == user_role and rule["system"] == system_id:
            matching_rules.append(rule)
            
            # Check if requested access level is allowed
            if access_level not in rule["access_levels"]:
                violations.append(f"Role {user_role} not authorized for {access_level} access to {system_id}")
                continue
                
            # Check additional conditions
            conditions = rule.get("conditions", {})
            if not _validate_conditions(conditions, user_data):
                violations.append(f"User does not meet conditions for {system_id} access")
                continue
                
    if not matching_rules:
        violations.append(f"No RBAC rule found for role {user_role} accessing {system_id}")
        
    evaluations = [
        PolicyEvaluation(
            policy_id=rule["id"],
            policy_name=f"RBAC Rule - {rule['role']} to {rule['system']}",
            matched=True,
            action=ActionType.APPROVE if access_level in rule["access_levels"] else ActionType.DENY,
            confidence=0.95,
            reasoning=f"RBAC rule evaluation for {user_role} accessing {system_id}"
        ) for rule in matching_rules
    ]
    
    return {
        "allowed": len(violations) == 0,
        "violations": violations,
        "evaluations": evaluations
    }


def _check_sensitivity_rules(sensitivity_rules: List[Dict], user_role: str, 
                           sensitivity_tier: str, user_data: Dict) -> Dict[str, Any]:
    """Check sensitivity tier access rules"""
    violations = []
    evaluations = []
    
    for rule in sensitivity_rules:
        if rule["sensitivity_tier"] == sensitivity_tier:
            allowed_roles = rule["allowed_roles"]
            
            if "all_employees" in allowed_roles or user_role in allowed_roles:
                # Check conditions
                conditions = rule.get("conditions", {})
                if not _validate_conditions(conditions, user_data):
                    violations.append(f"User does not meet {sensitivity_tier} tier conditions")
                    
                evaluations.append(
                    PolicyEvaluation(
                        policy_id=rule["id"],
                        policy_name=f"Sensitivity Rule - {sensitivity_tier}",
                        matched=True,
                        action=ActionType.APPROVE if len(violations) == 0 else ActionType.DENY,
                        confidence=0.9,
                        reasoning=f"Sensitivity tier {sensitivity_tier} access evaluation"
                    )
                )
            else:
                violations.append(f"Role {user_role} not authorized for {sensitivity_tier} tier access")
                
    return {
        "allowed": len(violations) == 0,
        "violations": violations,
        "evaluations": evaluations
    }


def _check_departmental_policies(dept_policies: List[Dict], user_dept: str, 
                               system_id: str, request_data: Dict) -> Dict[str, Any]:
    """Check departmental access policies"""
    evaluations = []
    requires_escalation = False
    conditions = []
    
    for policy in dept_policies:
        if (policy["department"] == user_dept and 
            (system_id in policy["systems_affected"] or "all" in policy["systems_affected"])):
            
            # Cross-department access requires escalation
            if "cross-department" in policy["policy"].lower():
                requires_escalation = True
                conditions.append("CISO approval required for cross-department access")
                
            # Emergency access policies
            if request_data.get("is_emergency") and "emergency" in policy["policy"].lower():
                conditions.append("Immediate notification to compliance director")
                
            evaluations.append(
                PolicyEvaluation(
                    policy_id=policy["id"],
                    policy_name=f"Department Policy - {user_dept}",
                    matched=True,
                    action=ActionType.ESCALATE if requires_escalation else ActionType.APPROVE,
                    confidence=0.85,
                    reasoning=policy["policy"]
                )
            )
            
    return {
        "evaluations": evaluations,
        "requires_escalation": requires_escalation,
        "conditions": conditions
    }


def _check_regulatory_constraints(reg_constraints: List[Dict], system_id: str, 
                                user_role: str, user_data: Dict) -> Dict[str, Any]:
    """Check regulatory compliance constraints"""
    evaluations = []
    violations = []
    flags = []
    compliant = True
    
    for constraint in reg_constraints:
        if (system_id in constraint["applies_to_systems"] or 
            user_role in constraint.get("applies_to_roles", [])):
            
            cert_required = constraint.get("certification_required")
            if cert_required and constraint["is_mandatory"]:
                cert_field = f"{cert_required}_date"
                cert_date = user_data.get(cert_field)
                
                if not cert_date:
                    violations.append(f"Missing required certification: {cert_required}")
                    compliant = False
                else:
                    # Check if certification is still valid
                    cert_datetime = datetime.fromisoformat(cert_date.replace("Z", "+00:00"))
                    validity_days = constraint["certification_validity_days"]
                    expiry_date = cert_datetime + timedelta(days=validity_days)
                    
                    if datetime.now() > expiry_date:
                        violations.append(f"Expired certification: {cert_required}")
                        compliant = False
                    elif (expiry_date - datetime.now()).days < 30:
                        flags.append(f"Certification {cert_required} expires soon")
                        
            evaluations.append(
                PolicyEvaluation(
                    policy_id=constraint["id"],
                    policy_name=f"Regulatory - {constraint['regulation_name']}",
                    matched=True,
                    action=ActionType.APPROVE if compliant else ActionType.DENY,
                    confidence=0.98,
                    reasoning=constraint["description"],
                    regulatory_flags=[constraint["regulator"]]
                )
            )
            
    return {
        "compliant": compliant,
        "violations": violations,
        "flags": flags,
        "evaluations": evaluations
    }


def _validate_conditions(conditions: Dict, user_data: Dict) -> bool:
    """Validate user meets policy conditions"""
    for condition_key, condition_value in conditions.items():
        if condition_key == "background_check_required" and condition_value:
            if not user_data.get("background_check_date"):
                return False
        elif condition_key == "privacy_training_required" and condition_value:
            if not user_data.get("privacy_training_date"):
                return False
        elif condition_key == "model_risk_training_required" and condition_value:
            if not user_data.get("model_risk_training_date"):
                return False
        elif condition_key == "sox_certification_required" and condition_value:
            if not user_data.get("sox_certification_date"):
                return False
        elif condition_key == "department":
            if user_data.get("department") != condition_value:
                return False
                
    return True


def _calculate_confidence(evaluations: List[PolicyEvaluation]) -> float:
    """Calculate overall confidence score for policy evaluation"""
    if not evaluations:
        return 0.0
        
    total_confidence = sum(eval_result.confidence for eval_result in evaluations)
    return min(total_confidence / len(evaluations), 1.0)