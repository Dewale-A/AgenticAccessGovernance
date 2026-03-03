"""Entitlement Lookup Tool - Look up current user access and history"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path


logger = logging.getLogger(__name__)


def lookup_user_entitlements(user_id: str, include_history: bool = True) -> Dict[str, Any]:
    """
    Look up user's current entitlements and access history.
    
    Args:
        user_id: User identifier
        include_history: Whether to include access history analysis
        
    Returns:
        User entitlement information and access patterns
    """
    try:
        # Load entitlements data
        entitlements_path = Path("data/entitlements.json")
        with open(entitlements_path, "r") as f:
            all_entitlements = json.load(f)
            
        # Load systems data for context
        systems_path = Path("data/systems.json")
        with open(systems_path, "r") as f:
            systems_data = json.load(f)
            
        # Filter entitlements for user
        user_entitlements = [ent for ent in all_entitlements if ent["user_id"] == user_id]
        
        # Separate active and inactive entitlements
        active_entitlements = [ent for ent in user_entitlements if ent["is_active"]]
        inactive_entitlements = [ent for ent in user_entitlements if not ent["is_active"]]
        
        # Enrich with system information
        enriched_active = _enrich_entitlements(active_entitlements, systems_data)
        enriched_inactive = _enrich_entitlements(inactive_entitlements, systems_data)
        
        # Analyze access patterns
        access_analysis = _analyze_access_patterns(enriched_active, systems_data)
        
        # Generate access summary
        access_summary = _generate_access_summary(enriched_active, systems_data)
        
        result = {
            "user_id": user_id,
            "current_entitlements": enriched_active,
            "inactive_entitlements": enriched_inactive,
            "access_summary": access_summary,
            "access_analysis": access_analysis,
            "risk_indicators": _identify_risk_indicators(enriched_active, access_analysis)
        }
        
        if include_history:
            result["access_history"] = _analyze_access_history(user_entitlements)
            
        return result
        
    except Exception as e:
        logger.error(f"Entitlement lookup failed: {str(e)}")
        return {
            "user_id": user_id,
            "error": f"Entitlement lookup error: {str(e)}",
            "current_entitlements": [],
            "access_summary": {"error": "Unable to retrieve entitlements"}
        }


# Simple function instead of tool decorator
def check_system_access(user_id: str, system_id: str) -> Dict[str, Any]:
    """
    Check if user has access to a specific system and access details.
    
    Args:
        user_id: User identifier
        system_id: System identifier
        
    Returns:
        System access information for the user
    """
    try:
        entitlements_result = lookup_user_entitlements(user_id, include_history=False)
        
        # Find entitlement for the specific system
        system_entitlement = None
        for ent in entitlements_result.get("current_entitlements", []):
            if ent["system_id"] == system_id:
                system_entitlement = ent
                break
        
        if system_entitlement:
            return {
                "has_access": True,
                "access_level": system_entitlement["access_level"],
                "granted_date": system_entitlement["granted_date"],
                "granted_by": system_entitlement["granted_by"],
                "last_used": system_entitlement.get("last_used"),
                "expires_date": system_entitlement.get("expires_date"),
                "system_info": system_entitlement.get("system_info", {})
            }
        else:
            return {
                "has_access": False,
                "system_id": system_id,
                "reason": "No active entitlement found for this system"
            }
            
    except Exception as e:
        logger.error(f"System access check failed: {str(e)}")
        return {
            "has_access": False,
            "error": f"Access check error: {str(e)}"
        }


def _enrich_entitlements(entitlements: List[Dict], systems_data: List[Dict]) -> List[Dict]:
    """Enrich entitlements with system information"""
    enriched = []
    
    for ent in entitlements:
        enriched_ent = ent.copy()
        
        # Find system information
        system_info = next((s for s in systems_data if s["id"] == ent["system_id"]), None)
        if system_info:
            enriched_ent["system_info"] = {
                "name": system_info["name"],
                "description": system_info["description"],
                "sensitivity_tier": system_info["sensitivity_tier"],
                "owner_department": system_info["owner_department"],
                "regulator": system_info.get("regulator"),
                "data_sensitivity_score": system_info.get("data_sensitivity_score", 0)
            }
        
        # Calculate access age
        granted_date = datetime.fromisoformat(ent["granted_date"].replace("Z", "+00:00"))
        access_age_days = (datetime.now() - granted_date).days
        enriched_ent["access_age_days"] = access_age_days
        
        # Calculate days since last use
        if ent.get("last_used"):
            last_used_date = datetime.fromisoformat(ent["last_used"].replace("Z", "+00:00"))
            days_since_use = (datetime.now() - last_used_date).days
            enriched_ent["days_since_last_use"] = days_since_use
        
        # Check if access is expiring soon
        if ent.get("expires_date"):
            expires_date = datetime.fromisoformat(ent["expires_date"].replace("Z", "+00:00"))
            days_until_expiry = (expires_date - datetime.now()).days
            enriched_ent["days_until_expiry"] = days_until_expiry
            enriched_ent["expires_soon"] = days_until_expiry <= 30
        
        enriched.append(enriched_ent)
    
    return enriched


def _analyze_access_patterns(entitlements: List[Dict], systems_data: List[Dict]) -> Dict[str, Any]:
    """Analyze user's access patterns for insights"""
    
    if not entitlements:
        return {"total_systems": 0, "analysis": "No active entitlements"}
    
    # Basic statistics
    total_systems = len(entitlements)
    access_levels = [ent["access_level"] for ent in entitlements]
    
    # Analyze by sensitivity tier
    sensitivity_distribution = {}
    department_distribution = {}
    regulator_distribution = {}
    
    for ent in entitlements:
        system_info = ent.get("system_info", {})
        
        # Sensitivity tier analysis
        sensitivity = system_info.get("sensitivity_tier", "Unknown")
        sensitivity_distribution[sensitivity] = sensitivity_distribution.get(sensitivity, 0) + 1
        
        # Department analysis
        dept = system_info.get("owner_department", "Unknown")
        department_distribution[dept] = department_distribution.get(dept, 0) + 1
        
        # Regulator analysis
        regulator = system_info.get("regulator")
        if regulator:
            regulator_distribution[regulator] = regulator_distribution.get(regulator, 0) + 1
    
    # Calculate risk metrics
    high_risk_count = sum(1 for ent in entitlements 
                         if ent.get("system_info", {}).get("sensitivity_tier") == "Restricted")
    
    admin_access_count = sum(1 for level in access_levels if level == "admin")
    
    # Identify dormant access
    dormant_access = []
    for ent in entitlements:
        days_since_use = ent.get("days_since_last_use")
        if days_since_use and days_since_use > 90:  # Not used in 90 days
            dormant_access.append({
                "system_id": ent["system_id"],
                "system_name": ent.get("system_info", {}).get("name", "Unknown"),
                "days_since_use": days_since_use,
                "access_level": ent["access_level"]
            })
    
    # Cross-department access analysis
    cross_dept_systems = []
    user_departments = list(department_distribution.keys())
    
    for ent in entitlements:
        system_dept = ent.get("system_info", {}).get("owner_department")
        if system_dept and len(user_departments) > 1:
            cross_dept_systems.append({
                "system_id": ent["system_id"],
                "system_name": ent.get("system_info", {}).get("name", "Unknown"),
                "owner_department": system_dept,
                "access_level": ent["access_level"]
            })
    
    return {
        "total_systems": total_systems,
        "access_level_distribution": dict(zip(*map(list, zip(*[[level, access_levels.count(level)] 
                                                               for level in set(access_levels)])))),
        "sensitivity_distribution": sensitivity_distribution,
        "department_distribution": department_distribution,
        "regulator_distribution": regulator_distribution,
        "high_risk_system_count": high_risk_count,
        "admin_access_count": admin_access_count,
        "cross_department_access": len(cross_dept_systems) > 0,
        "cross_dept_systems": cross_dept_systems[:5],  # Top 5
        "dormant_access_count": len(dormant_access),
        "dormant_systems": dormant_access[:5]  # Top 5 most dormant
    }


def _generate_access_summary(entitlements: List[Dict], systems_data: List[Dict]) -> Dict[str, Any]:
    """Generate high-level access summary"""
    
    if not entitlements:
        return {
            "status": "No Active Access",
            "summary": "User has no active system entitlements",
            "recommendations": ["Review user role and grant appropriate access"]
        }
    
    total_systems = len(entitlements)
    
    # Categorize systems
    restricted_systems = [ent for ent in entitlements 
                         if ent.get("system_info", {}).get("sensitivity_tier") == "Restricted"]
    
    confidential_systems = [ent for ent in entitlements 
                           if ent.get("system_info", {}).get("sensitivity_tier") == "Confidential"]
    
    admin_access = [ent for ent in entitlements if ent["access_level"] == "admin"]
    
    # Generate status
    if len(restricted_systems) > 3 or len(admin_access) > 2:
        status = "High Privilege User"
    elif len(restricted_systems) > 0 or len(confidential_systems) > 2:
        status = "Elevated Access User"
    else:
        status = "Standard Access User"
    
    # Generate summary
    summary_parts = [
        f"Access to {total_systems} systems",
        f"{len(restricted_systems)} restricted systems" if restricted_systems else None,
        f"{len(confidential_systems)} confidential systems" if confidential_systems else None,
        f"{len(admin_access)} admin privileges" if admin_access else None
    ]
    
    summary = ", ".join(filter(None, summary_parts))
    
    # Generate recommendations
    recommendations = []
    
    # Check for dormant access
    dormant_count = sum(1 for ent in entitlements 
                       if ent.get("days_since_last_use", 0) > 90)
    if dormant_count > 0:
        recommendations.append(f"Review {dormant_count} systems with dormant access")
    
    # Check for expiring access
    expiring_count = sum(1 for ent in entitlements 
                        if ent.get("expires_soon", False))
    if expiring_count > 0:
        recommendations.append(f"Renew {expiring_count} expiring access grants")
    
    # Check for over-privileged access
    if len(admin_access) > 3:
        recommendations.append("Review administrative access - may be over-privileged")
    
    if not recommendations:
        recommendations.append("Access profile appears appropriate")
    
    return {
        "status": status,
        "summary": summary,
        "restricted_system_count": len(restricted_systems),
        "admin_access_count": len(admin_access),
        "recommendations": recommendations
    }


def _analyze_access_history(entitlements: List[Dict]) -> Dict[str, Any]:
    """Analyze historical access patterns"""
    
    # Calculate access grants over time
    grants_by_month = {}
    access_changes = []
    
    for ent in entitlements:
        granted_date = datetime.fromisoformat(ent["granted_date"].replace("Z", "+00:00"))
        month_key = granted_date.strftime("%Y-%m")
        grants_by_month[month_key] = grants_by_month.get(month_key, 0) + 1
        
        access_changes.append({
            "date": granted_date.isoformat(),
            "action": "GRANTED",
            "system_id": ent["system_id"],
            "access_level": ent["access_level"],
            "granted_by": ent["granted_by"]
        })
        
        # Check for revocations (inactive entitlements)
        if not ent["is_active"]:
            # Estimate revocation date (simplified - would need audit log in real system)
            estimated_revoke_date = granted_date + timedelta(days=365)  # Assume 1 year default
            access_changes.append({
                "date": estimated_revoke_date.isoformat(),
                "action": "REVOKED",
                "system_id": ent["system_id"],
                "access_level": ent["access_level"],
                "reason": "Access deactivated"
            })
    
    # Sort changes chronologically
    access_changes.sort(key=lambda x: x["date"])
    
    # Identify patterns
    patterns = []
    
    # Bulk access grants
    if any(count > 5 for count in grants_by_month.values()):
        patterns.append("Bulk access provisioning detected")
    
    # Frequent access changes
    if len(access_changes) > 20:
        patterns.append("High frequency of access changes")
    
    return {
        "total_access_changes": len(access_changes),
        "grants_by_month": grants_by_month,
        "recent_changes": access_changes[-10:],  # Last 10 changes
        "access_patterns": patterns,
        "first_access_date": min(change["date"] for change in access_changes) if access_changes else None,
        "most_recent_change": max(change["date"] for change in access_changes) if access_changes else None
    }


def _identify_risk_indicators(entitlements: List[Dict], access_analysis: Dict[str, Any]) -> List[str]:
    """Identify risk indicators from access patterns"""
    indicators = []
    
    # High privilege indicators
    if access_analysis.get("admin_access_count", 0) > 3:
        indicators.append("Excessive administrative privileges")
    
    if access_analysis.get("high_risk_system_count", 0) > 2:
        indicators.append("Access to multiple high-risk systems")
    
    # Cross-department access
    dept_count = len(access_analysis.get("department_distribution", {}))
    if dept_count > 2:
        indicators.append(f"Cross-department access ({dept_count} departments)")
    
    # Dormant access
    dormant_count = access_analysis.get("dormant_access_count", 0)
    if dormant_count > 3:
        indicators.append(f"Multiple dormant access grants ({dormant_count})")
    
    # Regulatory system access
    reg_count = len(access_analysis.get("regulator_distribution", {}))
    if reg_count > 2:
        indicators.append(f"Access to systems under multiple regulators ({reg_count})")
    
    # Age of access
    old_access = [ent for ent in entitlements if ent.get("access_age_days", 0) > 1095]  # 3 years
    if len(old_access) > 5:
        indicators.append("Multiple long-standing access grants")
    
    # Sensitivity tier concentration
    sensitivity_dist = access_analysis.get("sensitivity_distribution", {})
    if sensitivity_dist.get("Restricted", 0) > 3:
        indicators.append("High concentration of restricted system access")
    
    return indicators