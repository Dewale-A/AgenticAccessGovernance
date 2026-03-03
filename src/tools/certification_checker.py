"""Certification Checker Tool - Check user training certifications and compliance"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

from crewai import tool
from src.config.settings import settings

logger = logging.getLogger(__name__)


@tool("Certification Checker")
def check_user_certifications(user_id: str, required_certifications: List[str] = None) -> Dict[str, Any]:
    """
    Check user's training certifications and compliance status.
    
    Args:
        user_id: User identifier
        required_certifications: List of required certification types
        
    Returns:
        Certification status and compliance information
    """
    try:
        # Load user data
        users_path = Path("data/users.json")
        with open(users_path, "r") as f:
            users_data = json.load(f)
        
        # Find user
        user_data = next((u for u in users_data if u["id"] == user_id), None)
        if not user_data:
            return {
                "user_id": user_id,
                "error": "User not found",
                "compliance_status": "UNKNOWN"
            }
        
        # Check all certifications
        cert_status = {}
        compliance_issues = []
        expiring_soon = []
        
        # Define certification checks
        cert_checks = {
            "privacy_training": {
                "field": "privacy_training_date",
                "validity_days": settings.privacy_training_valid_days,
                "description": "Privacy Training (PIPEDA compliance)"
            },
            "model_risk_training": {
                "field": "model_risk_training_date", 
                "validity_days": settings.model_risk_training_valid_days,
                "description": "Model Risk Training (SR 11-7 compliance)"
            },
            "background_check": {
                "field": "background_check_date",
                "validity_days": settings.background_check_valid_days,
                "description": "Background Check (OSFI B-13 compliance)"
            },
            "sox_certification": {
                "field": "sox_certification_date",
                "validity_days": settings.sox_certification_valid_days,
                "description": "SOX Certification (Sarbanes-Oxley compliance)"
            }
        }
        
        # Check each certification
        for cert_type, cert_config in cert_checks.items():
            status = _check_single_certification(user_data, cert_type, cert_config)
            cert_status[cert_type] = status
            
            if status["status"] == "EXPIRED":
                compliance_issues.append(f"{cert_config['description']} expired")
            elif status["status"] == "MISSING":
                compliance_issues.append(f"{cert_config['description']} not completed")
            elif status["status"] == "EXPIRING_SOON":
                expiring_soon.append(f"{cert_config['description']} expires in {status['days_until_expiry']} days")
        
        # Filter by required certifications if specified
        if required_certifications:
            filtered_status = {k: v for k, v in cert_status.items() if k in required_certifications}
            filtered_issues = [issue for issue in compliance_issues 
                             if any(cert in issue.lower().replace(" ", "_").replace("(", "").replace(")", "") 
                                   for cert in required_certifications)]
            cert_status = filtered_status
            compliance_issues = filtered_issues
        
        # Determine overall compliance status
        overall_status = _determine_overall_compliance(cert_status)
        
        # Generate recommendations
        recommendations = _generate_cert_recommendations(cert_status, compliance_issues, expiring_soon)
        
        return {
            "user_id": user_id,
            "user_name": user_data.get("name"),
            "compliance_status": overall_status,
            "certification_details": cert_status,
            "compliance_issues": compliance_issues,
            "certifications_expiring_soon": expiring_soon,
            "recommendations": recommendations,
            "last_checked": datetime.now().isoformat(),
            "regulatory_risk": _assess_regulatory_risk(cert_status, user_data)
        }
        
    except Exception as e:
        logger.error(f"Certification check failed: {str(e)}")
        return {
            "user_id": user_id,
            "error": f"Certification check error: {str(e)}",
            "compliance_status": "ERROR"
        }


@tool("Bulk Certification Review")
def review_department_certifications(department: str = None, expired_only: bool = False) -> Dict[str, Any]:
    """
    Review certifications for a department or all users.
    
    Args:
        department: Department to review (None for all)
        expired_only: Only return users with expired certifications
        
    Returns:
        Department certification review results
    """
    try:
        # Load user data
        users_path = Path("data/users.json")
        with open(users_path, "r") as f:
            users_data = json.load(f)
        
        # Filter by department if specified
        if department:
            users_data = [u for u in users_data if u.get("department") == department]
        
        review_results = []
        summary_stats = {
            "total_users": len(users_data),
            "compliant_users": 0,
            "non_compliant_users": 0,
            "users_with_expiring_certs": 0,
            "certification_summary": {}
        }
        
        for user in users_data:
            user_cert_check = check_user_certifications(user["id"])
            
            # Skip if checking failed
            if "error" in user_cert_check:
                continue
            
            compliance_status = user_cert_check["compliance_status"]
            
            # Update summary stats
            if compliance_status == "COMPLIANT":
                summary_stats["compliant_users"] += 1
            else:
                summary_stats["non_compliant_users"] += 1
            
            if user_cert_check.get("certifications_expiring_soon"):
                summary_stats["users_with_expiring_certs"] += 1
            
            # Filter for expired only if requested
            if expired_only and compliance_status == "COMPLIANT":
                continue
            
            # Add to results
            review_results.append({
                "user_id": user["id"],
                "user_name": user["name"],
                "department": user["department"],
                "role": user["role"],
                "compliance_status": compliance_status,
                "issues": user_cert_check.get("compliance_issues", []),
                "expiring_soon": user_cert_check.get("certifications_expiring_soon", []),
                "regulatory_risk": user_cert_check.get("regulatory_risk", "LOW")
            })
            
            # Update certification summary
            cert_details = user_cert_check.get("certification_details", {})
            for cert_type, cert_info in cert_details.items():
                if cert_type not in summary_stats["certification_summary"]:
                    summary_stats["certification_summary"][cert_type] = {
                        "valid": 0, "expired": 0, "missing": 0, "expiring_soon": 0
                    }
                
                status = cert_info["status"]
                if status == "VALID":
                    summary_stats["certification_summary"][cert_type]["valid"] += 1
                elif status == "EXPIRED":
                    summary_stats["certification_summary"][cert_type]["expired"] += 1
                elif status == "MISSING":
                    summary_stats["certification_summary"][cert_type]["missing"] += 1
                elif status == "EXPIRING_SOON":
                    summary_stats["certification_summary"][cert_type]["expiring_soon"] += 1
        
        # Generate department recommendations
        dept_recommendations = _generate_department_recommendations(summary_stats, review_results)
        
        return {
            "department": department or "ALL_DEPARTMENTS",
            "review_date": datetime.now().isoformat(),
            "summary_statistics": summary_stats,
            "user_reviews": review_results,
            "department_recommendations": dept_recommendations,
            "high_risk_users": [r for r in review_results if r["regulatory_risk"] == "HIGH"][:10]
        }
        
    except Exception as e:
        logger.error(f"Department certification review failed: {str(e)}")
        return {
            "department": department or "ALL_DEPARTMENTS",
            "error": f"Review error: {str(e)}",
            "review_date": datetime.now().isoformat()
        }


@tool("Certification Renewal Reminder")
def generate_renewal_reminders(days_ahead: int = 30) -> Dict[str, Any]:
    """
    Generate renewal reminders for certifications expiring soon.
    
    Args:
        days_ahead: Number of days ahead to check for expiring certifications
        
    Returns:
        List of users needing certification renewals
    """
    try:
        # Load user data
        users_path = Path("data/users.json")
        with open(users_path, "r") as f:
            users_data = json.load(f)
        
        renewal_reminders = []
        
        for user in users_data:
            user_cert_check = check_user_certifications(user["id"])
            
            if "error" in user_cert_check:
                continue
            
            cert_details = user_cert_check.get("certification_details", {})
            user_reminders = []
            
            for cert_type, cert_info in cert_details.items():
                if cert_info["status"] in ["EXPIRING_SOON", "EXPIRED"]:
                    days_until_expiry = cert_info.get("days_until_expiry", 0)
                    
                    if days_until_expiry <= days_ahead or cert_info["status"] == "EXPIRED":
                        user_reminders.append({
                            "certification_type": cert_type,
                            "description": cert_info["description"],
                            "status": cert_info["status"],
                            "days_until_expiry": days_until_expiry,
                            "expired_date" if cert_info["status"] == "EXPIRED" else "expiry_date": cert_info.get("expiry_date"),
                            "priority": "HIGH" if cert_info["status"] == "EXPIRED" else "MEDIUM"
                        })
            
            if user_reminders:
                renewal_reminders.append({
                    "user_id": user["id"],
                    "user_name": user["name"],
                    "email": user["email"],
                    "department": user["department"],
                    "manager_id": user.get("manager_id"),
                    "certifications_to_renew": user_reminders,
                    "highest_priority": max(r["priority"] for r in user_reminders)
                })
        
        # Sort by priority and expiry date
        renewal_reminders.sort(key=lambda x: (
            x["highest_priority"] == "HIGH", 
            min(r.get("days_until_expiry", 999) for r in x["certifications_to_renew"])
        ), reverse=True)
        
        return {
            "reminder_date": datetime.now().isoformat(),
            "days_ahead_checked": days_ahead,
            "total_users_needing_renewal": len(renewal_reminders),
            "high_priority_count": len([r for r in renewal_reminders if r["highest_priority"] == "HIGH"]),
            "renewal_reminders": renewal_reminders,
            "summary_by_certification": _summarize_renewals_by_cert_type(renewal_reminders)
        }
        
    except Exception as e:
        logger.error(f"Renewal reminder generation failed: {str(e)}")
        return {
            "reminder_date": datetime.now().isoformat(),
            "error": f"Reminder generation error: {str(e)}",
            "renewal_reminders": []
        }


def _check_single_certification(user_data: Dict, cert_type: str, cert_config: Dict) -> Dict[str, Any]:
    """Check a single certification for a user"""
    cert_field = cert_config["field"]
    validity_days = cert_config["validity_days"]
    description = cert_config["description"]
    
    cert_date_str = user_data.get(cert_field)
    
    if not cert_date_str:
        return {
            "status": "MISSING",
            "description": description,
            "message": "Certification not completed",
            "required": True
        }
    
    # Parse certification date
    try:
        cert_date = datetime.fromisoformat(cert_date_str.replace("Z", "+00:00"))
        expiry_date = cert_date + timedelta(days=validity_days)
        days_until_expiry = (expiry_date - datetime.now()).days
        
        if days_until_expiry < 0:
            return {
                "status": "EXPIRED",
                "description": description,
                "certification_date": cert_date.isoformat(),
                "expiry_date": expiry_date.isoformat(),
                "days_expired": abs(days_until_expiry),
                "message": f"Expired {abs(days_until_expiry)} days ago"
            }
        elif days_until_expiry <= 30:  # Expiring within 30 days
            return {
                "status": "EXPIRING_SOON",
                "description": description,
                "certification_date": cert_date.isoformat(),
                "expiry_date": expiry_date.isoformat(),
                "days_until_expiry": days_until_expiry,
                "message": f"Expires in {days_until_expiry} days"
            }
        else:
            return {
                "status": "VALID",
                "description": description,
                "certification_date": cert_date.isoformat(),
                "expiry_date": expiry_date.isoformat(),
                "days_until_expiry": days_until_expiry,
                "message": f"Valid for {days_until_expiry} days"
            }
    
    except ValueError:
        return {
            "status": "INVALID_DATE",
            "description": description,
            "message": "Invalid certification date format",
            "raw_date": cert_date_str
        }


def _determine_overall_compliance(cert_status: Dict[str, Dict]) -> str:
    """Determine overall compliance status"""
    statuses = [cert["status"] for cert in cert_status.values()]
    
    if "EXPIRED" in statuses or "MISSING" in statuses:
        return "NON_COMPLIANT"
    elif "EXPIRING_SOON" in statuses:
        return "COMPLIANT_WITH_WARNINGS"
    elif all(status == "VALID" for status in statuses):
        return "COMPLIANT"
    else:
        return "PARTIAL_COMPLIANCE"


def _assess_regulatory_risk(cert_status: Dict[str, Dict], user_data: Dict) -> str:
    """Assess regulatory risk based on certification status and user role"""
    expired_count = sum(1 for cert in cert_status.values() if cert["status"] == "EXPIRED")
    missing_count = sum(1 for cert in cert_status.values() if cert["status"] == "MISSING")
    
    # High-risk roles
    high_risk_roles = ["branch_manager", "risk_manager", "compliance_officer", "ciso", "treasury_vp"]
    user_role = user_data.get("role", "")
    
    # High-risk departments
    high_risk_depts = ["Risk Management", "Compliance", "Treasury"]
    user_dept = user_data.get("department", "")
    
    if (expired_count + missing_count) > 2:
        return "HIGH"
    elif (expired_count + missing_count) > 0 and (user_role in high_risk_roles or user_dept in high_risk_depts):
        return "HIGH"
    elif (expired_count + missing_count) > 0:
        return "MEDIUM"
    else:
        return "LOW"


def _generate_cert_recommendations(cert_status: Dict, issues: List[str], expiring: List[str]) -> List[str]:
    """Generate certification recommendations"""
    recommendations = []
    
    if issues:
        recommendations.append("Immediate action required: Complete missing/expired certifications before accessing restricted systems")
    
    if expiring:
        recommendations.append("Schedule certification renewals for expiring certifications")
    
    # Specific recommendations by certification type
    for cert_type, cert_info in cert_status.items():
        if cert_info["status"] == "EXPIRED":
            if cert_type == "privacy_training":
                recommendations.append("Complete privacy training immediately - required for PIPEDA compliance")
            elif cert_type == "model_risk_training":
                recommendations.append("Complete model risk training - required for SR 11-7 compliance")
            elif cert_type == "background_check":
                recommendations.append("Update background check - required for OSFI B-13 compliance")
            elif cert_type == "sox_certification":
                recommendations.append("Renew SOX certification - required for financial system access")
    
    if not recommendations:
        recommendations.append("All certifications are current - maintain regular renewal schedule")
    
    return recommendations


def _generate_department_recommendations(summary_stats: Dict, review_results: List[Dict]) -> List[str]:
    """Generate department-level recommendations"""
    recommendations = []
    
    total_users = summary_stats["total_users"]
    non_compliant = summary_stats["non_compliant_users"]
    
    if total_users == 0:
        return ["No users found in specified department"]
    
    # Compliance rate analysis
    compliance_rate = (summary_stats["compliant_users"] / total_users) * 100
    
    if compliance_rate < 70:
        recommendations.append(f"URGENT: Low compliance rate ({compliance_rate:.1f}%) - implement immediate certification drive")
    elif compliance_rate < 90:
        recommendations.append(f"Moderate compliance rate ({compliance_rate:.1f}%) - increase training awareness")
    else:
        recommendations.append(f"Good compliance rate ({compliance_rate:.1f}%) - maintain current practices")
    
    # Specific certification issues
    cert_summary = summary_stats.get("certification_summary", {})
    for cert_type, cert_stats in cert_summary.items():
        total_cert = sum(cert_stats.values())
        if total_cert > 0:
            expired_rate = (cert_stats["expired"] / total_cert) * 100
            missing_rate = (cert_stats["missing"] / total_cert) * 100
            
            if expired_rate > 20:
                recommendations.append(f"High {cert_type} expiry rate ({expired_rate:.1f}%) - schedule renewal campaign")
            if missing_rate > 10:
                recommendations.append(f"High {cert_type} missing rate ({missing_rate:.1f}%) - mandatory training required")
    
    # High-risk users
    high_risk_count = len([r for r in review_results if r["regulatory_risk"] == "HIGH"])
    if high_risk_count > 0:
        recommendations.append(f"Priority attention needed for {high_risk_count} high-risk users")
    
    return recommendations


def _summarize_renewals_by_cert_type(renewal_reminders: List[Dict]) -> Dict[str, Any]:
    """Summarize renewal needs by certification type"""
    cert_summary = {}
    
    for reminder in renewal_reminders:
        for cert in reminder["certifications_to_renew"]:
            cert_type = cert["certification_type"]
            
            if cert_type not in cert_summary:
                cert_summary[cert_type] = {
                    "total_users": 0,
                    "expired": 0,
                    "expiring_soon": 0,
                    "avg_days_until_expiry": 0
                }
            
            cert_summary[cert_type]["total_users"] += 1
            
            if cert["status"] == "EXPIRED":
                cert_summary[cert_type]["expired"] += 1
            else:
                cert_summary[cert_type]["expiring_soon"] += 1
    
    return cert_summary