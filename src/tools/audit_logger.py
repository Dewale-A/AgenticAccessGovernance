"""Audit Logger Tool - Log all decisions with full traceability"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

from src.models.access_request import AuditRecord

logger = logging.getLogger(__name__)


# Simple function instead of tool decorator
def log_decision(request_id: str, agent_name: str, action: str, decision: str, 
                reasoning: str, context_data: Dict[str, Any] = None,
                confidence_score: float = None) -> Dict[str, Any]:
    """
    Log an access governance decision with full audit trail.
    
    Args:
        request_id: Access request identifier
        agent_name: Name of the agent making the decision
        action: Action taken (evaluate, approve, deny, escalate)
        decision: Decision outcome
        reasoning: Detailed reasoning for the decision
        context_data: Additional context information
        confidence_score: Confidence level in the decision
        
    Returns:
        Audit log confirmation with record ID
    """
    try:
        # Create audit record
        audit_record = AuditRecord(
            request_id=request_id,
            timestamp=datetime.now(),
            agent_name=agent_name,
            action=action,
            decision=decision,
            reasoning=reasoning,
            confidence_score=confidence_score,
            metadata=context_data or {}
        )
        
        # Extract additional fields from context
        if context_data:
            audit_record.policies_evaluated = context_data.get("policies_evaluated", [])
            audit_record.risk_factors = context_data.get("risk_factors", [])
            audit_record.regulatory_considerations = context_data.get("regulatory_flags", [])
        
        # Generate record ID
        record_id = f"AUDIT_{request_id}_{agent_name}_{int(datetime.now().timestamp())}"
        
        # Ensure output directory exists
        output_dir = Path("output")
        output_dir.mkdir(exist_ok=True)
        
        # Write to audit log file
        audit_file = output_dir / f"audit_trail_{request_id}.json"
        
        # Load existing audit trail or create new
        audit_trail = []
        if audit_file.exists():
            with open(audit_file, "r") as f:
                audit_trail = json.load(f)
        
        # Add new record
        audit_entry = {
            "record_id": record_id,
            "request_id": request_id,
            "timestamp": audit_record.timestamp.isoformat(),
            "agent_name": agent_name,
            "action": action,
            "decision": decision,
            "reasoning": reasoning,
            "confidence_score": confidence_score,
            "policies_evaluated": audit_record.policies_evaluated,
            "risk_factors": audit_record.risk_factors,
            "regulatory_considerations": audit_record.regulatory_considerations,
            "metadata": audit_record.metadata
        }
        
        audit_trail.append(audit_entry)
        
        # Write back to file
        with open(audit_file, "w") as f:
            json.dump(audit_trail, f, indent=2)
        
        # Also append to master audit log
        master_log = output_dir / "master_audit_log.jsonl"
        with open(master_log, "a") as f:
            f.write(json.dumps(audit_entry) + "\n")
        
        # Log to application logger
        logger.info(f"Audit decision logged: {record_id} - {agent_name}: {decision}")
        
        return {
            "success": True,
            "record_id": record_id,
            "audit_file": str(audit_file),
            "timestamp": audit_record.timestamp.isoformat(),
            "message": f"Decision logged for request {request_id}"
        }
        
    except Exception as e:
        logger.error(f"Audit logging failed: {str(e)}")
        return {
            "success": False,
            "error": f"Audit logging error: {str(e)}",
            "request_id": request_id
        }


# Simple function instead of tool decorator
def get_audit_trail(request_id: str) -> Dict[str, Any]:
    """
    Retrieve complete audit trail for an access request.
    
    Args:
        request_id: Access request identifier
        
    Returns:
        Complete audit trail with decision chain
    """
    try:
        output_dir = Path("output")
        audit_file = output_dir / f"audit_trail_{request_id}.json"
        
        if not audit_file.exists():
            return {
                "request_id": request_id,
                "audit_trail": [],
                "summary": "No audit trail found",
                "total_records": 0
            }
        
        # Load audit trail
        with open(audit_file, "r") as f:
            audit_trail = json.load(f)
        
        # Generate summary
        summary = _generate_audit_summary(audit_trail)
        
        # Create decision chain
        decision_chain = _create_decision_chain(audit_trail)
        
        return {
            "request_id": request_id,
            "audit_trail": audit_trail,
            "decision_chain": decision_chain,
            "summary": summary,
            "total_records": len(audit_trail),
            "first_record": audit_trail[0]["timestamp"] if audit_trail else None,
            "last_record": audit_trail[-1]["timestamp"] if audit_trail else None
        }
        
    except Exception as e:
        logger.error(f"Audit trail retrieval failed: {str(e)}")
        return {
            "request_id": request_id,
            "error": f"Audit retrieval error: {str(e)}",
            "audit_trail": []
        }


# Simple function instead of tool decorator
def generate_compliance_report(start_date: str = None, end_date: str = None, 
                             request_ids: List[str] = None) -> Dict[str, Any]:
    """
    Generate compliance report from audit trails.
    
    Args:
        start_date: Start date for report (ISO format)
        end_date: End date for report (ISO format)
        request_ids: Specific request IDs to include
        
    Returns:
        Compliance report with statistics and findings
    """
    try:
        output_dir = Path("output")
        master_log = output_dir / "master_audit_log.jsonl"
        
        if not master_log.exists():
            return {
                "report_generated": datetime.now().isoformat(),
                "error": "No audit data available",
                "total_decisions": 0
            }
        
        # Load audit records
        audit_records = []
        with open(master_log, "r") as f:
            for line in f:
                record = json.loads(line.strip())
                
                # Filter by date range if specified
                if start_date or end_date:
                    record_date = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
                    
                    if start_date:
                        start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
                        if record_date < start_dt:
                            continue
                    
                    if end_date:
                        end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
                        if record_date > end_dt:
                            continue
                
                # Filter by request IDs if specified
                if request_ids and record["request_id"] not in request_ids:
                    continue
                
                audit_records.append(record)
        
        # Generate report statistics
        stats = _calculate_audit_statistics(audit_records)
        
        # Identify compliance issues
        compliance_issues = _identify_compliance_issues(audit_records)
        
        # Generate agent performance metrics
        agent_metrics = _calculate_agent_metrics(audit_records)
        
        # Create report
        report = {
            "report_generated": datetime.now().isoformat(),
            "report_period": {
                "start_date": start_date,
                "end_date": end_date,
                "total_records": len(audit_records)
            },
            "decision_statistics": stats,
            "compliance_findings": compliance_issues,
            "agent_performance": agent_metrics,
            "recommendations": _generate_compliance_recommendations(stats, compliance_issues)
        }
        
        # Save report
        report_file = output_dir / f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        return report
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {str(e)}")
        return {
            "report_generated": datetime.now().isoformat(),
            "error": f"Report generation error: {str(e)}",
            "total_decisions": 0
        }


def _generate_audit_summary(audit_trail: List[Dict]) -> Dict[str, Any]:
    """Generate summary of audit trail"""
    if not audit_trail:
        return {"status": "No audit records"}
    
    # Count decisions by type
    decisions = {}
    agents = set()
    actions = set()
    
    for record in audit_trail:
        decision = record["decision"]
        decisions[decision] = decisions.get(decision, 0) + 1
        agents.add(record["agent_name"])
        actions.add(record["action"])
    
    # Identify final decision
    final_record = audit_trail[-1]
    final_decision = final_record["decision"]
    
    # Calculate processing time
    start_time = datetime.fromisoformat(audit_trail[0]["timestamp"].replace("Z", "+00:00"))
    end_time = datetime.fromisoformat(final_record["timestamp"].replace("Z", "+00:00"))
    processing_time = (end_time - start_time).total_seconds()
    
    return {
        "final_decision": final_decision,
        "processing_time_seconds": processing_time,
        "total_steps": len(audit_trail),
        "agents_involved": list(agents),
        "actions_taken": list(actions),
        "decision_counts": decisions,
        "decision_maker": final_record["agent_name"],
        "confidence_score": final_record.get("confidence_score")
    }


def _create_decision_chain(audit_trail: List[Dict]) -> List[Dict]:
    """Create chronological decision chain"""
    chain = []
    
    for i, record in enumerate(audit_trail):
        step = {
            "step": i + 1,
            "timestamp": record["timestamp"],
            "agent": record["agent_name"],
            "action": record["action"],
            "decision": record["decision"],
            "key_reasoning": record["reasoning"][:200] + "..." if len(record["reasoning"]) > 200 else record["reasoning"],
            "confidence": record.get("confidence_score"),
            "risk_factors": record.get("risk_factors", [])[:3],  # Top 3
            "policies_evaluated": len(record.get("policies_evaluated", []))
        }
        chain.append(step)
    
    return chain


def _calculate_audit_statistics(records: List[Dict]) -> Dict[str, Any]:
    """Calculate audit statistics"""
    if not records:
        return {"total_decisions": 0}
    
    # Basic counts
    total_decisions = len(records)
    
    # Decision outcomes
    outcomes = {}
    for record in records:
        decision = record["decision"]
        outcomes[decision] = outcomes.get(decision, 0) + 1
    
    # Agent activity
    agent_activity = {}
    for record in records:
        agent = record["agent_name"]
        agent_activity[agent] = agent_activity.get(agent, 0) + 1
    
    # Time-based analysis
    timestamps = [datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) for r in records]
    
    # Average confidence scores
    confidence_scores = [r.get("confidence_score") for r in records if r.get("confidence_score")]
    avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else None
    
    # Policy evaluation frequency
    total_policies = sum(len(r.get("policies_evaluated", [])) for r in records)
    avg_policies_per_decision = total_policies / total_decisions if total_decisions > 0 else 0
    
    return {
        "total_decisions": total_decisions,
        "decision_outcomes": outcomes,
        "agent_activity": agent_activity,
        "time_period": {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_hours": (max(timestamps) - min(timestamps)).total_seconds() / 3600
        },
        "average_confidence_score": round(avg_confidence, 2) if avg_confidence else None,
        "average_policies_per_decision": round(avg_policies_per_decision, 1),
        "decisions_per_hour": round(total_decisions / ((max(timestamps) - min(timestamps)).total_seconds() / 3600 + 0.1), 2)
    }


def _identify_compliance_issues(records: List[Dict]) -> List[Dict]:
    """Identify potential compliance issues"""
    issues = []
    
    # Check for decisions without proper reasoning
    insufficient_reasoning = [r for r in records if len(r.get("reasoning", "")) < 20]
    if insufficient_reasoning:
        issues.append({
            "issue_type": "Insufficient Reasoning",
            "severity": "MEDIUM",
            "count": len(insufficient_reasoning),
            "description": "Decisions made without adequate justification",
            "affected_requests": [r["request_id"] for r in insufficient_reasoning[:5]]
        })
    
    # Check for low confidence decisions
    low_confidence = [r for r in records if r.get("confidence_score", 1.0) < 0.6]
    if low_confidence:
        issues.append({
            "issue_type": "Low Confidence Decisions",
            "severity": "HIGH",
            "count": len(low_confidence),
            "description": "Decisions made with low confidence scores",
            "affected_requests": [r["request_id"] for r in low_confidence[:5]]
        })
    
    # Check for missing policy evaluations
    no_policies = [r for r in records if not r.get("policies_evaluated")]
    if no_policies:
        issues.append({
            "issue_type": "Missing Policy Evaluations",
            "severity": "HIGH",
            "count": len(no_policies),
            "description": "Decisions made without policy evaluation",
            "affected_requests": [r["request_id"] for r in no_policies[:5]]
        })
    
    # Check for regulatory considerations
    no_regulatory = [r for r in records if not r.get("regulatory_considerations")]
    if len(no_regulatory) > len(records) * 0.8:  # More than 80% missing
        issues.append({
            "issue_type": "Missing Regulatory Analysis",
            "severity": "MEDIUM",
            "count": len(no_regulatory),
            "description": "High percentage of decisions without regulatory consideration",
            "affected_requests": [r["request_id"] for r in no_regulatory[:5]]
        })
    
    # Check for rapid decisions (potential insufficient review)
    rapid_decisions = []
    for record in records:
        if record.get("metadata", {}).get("processing_time_seconds", 0) < 5:
            rapid_decisions.append(record)
    
    if rapid_decisions:
        issues.append({
            "issue_type": "Rapid Decisions",
            "severity": "LOW",
            "count": len(rapid_decisions),
            "description": "Decisions made very quickly (under 5 seconds)",
            "affected_requests": [r["request_id"] for r in rapid_decisions[:5]]
        })
    
    return issues


def _calculate_agent_metrics(records: List[Dict]) -> Dict[str, Any]:
    """Calculate performance metrics for each agent"""
    agent_stats = {}
    
    for record in records:
        agent = record["agent_name"]
        
        if agent not in agent_stats:
            agent_stats[agent] = {
                "total_decisions": 0,
                "decisions_by_outcome": {},
                "confidence_scores": [],
                "policies_evaluated": [],
                "risk_factors_identified": []
            }
        
        stats = agent_stats[agent]
        stats["total_decisions"] += 1
        
        # Track decision outcomes
        decision = record["decision"]
        stats["decisions_by_outcome"][decision] = stats["decisions_by_outcome"].get(decision, 0) + 1
        
        # Track confidence scores
        if record.get("confidence_score"):
            stats["confidence_scores"].append(record["confidence_score"])
        
        # Track policy evaluations
        policies_count = len(record.get("policies_evaluated", []))
        stats["policies_evaluated"].append(policies_count)
        
        # Track risk factors
        risk_count = len(record.get("risk_factors", []))
        stats["risk_factors_identified"].append(risk_count)
    
    # Calculate derived metrics
    for agent, stats in agent_stats.items():
        # Average confidence
        if stats["confidence_scores"]:
            stats["avg_confidence"] = round(sum(stats["confidence_scores"]) / len(stats["confidence_scores"]), 2)
        
        # Average policies per decision
        if stats["policies_evaluated"]:
            stats["avg_policies_per_decision"] = round(sum(stats["policies_evaluated"]) / len(stats["policies_evaluated"]), 1)
        
        # Average risk factors identified
        if stats["risk_factors_identified"]:
            stats["avg_risk_factors"] = round(sum(stats["risk_factors_identified"]) / len(stats["risk_factors_identified"]), 1)
        
        # Decision quality score (simplified metric)
        quality_factors = []
        if stats.get("avg_confidence"):
            quality_factors.append(stats["avg_confidence"])
        if stats.get("avg_policies_per_decision"):
            quality_factors.append(min(stats["avg_policies_per_decision"] / 5, 1.0))  # Normalize to 1.0
        
        if quality_factors:
            stats["quality_score"] = round(sum(quality_factors) / len(quality_factors), 2)
    
    return agent_stats


def _generate_compliance_recommendations(stats: Dict[str, Any], issues: List[Dict]) -> List[str]:
    """Generate compliance recommendations based on findings"""
    recommendations = []
    
    # Based on issues found
    for issue in issues:
        if issue["issue_type"] == "Low Confidence Decisions":
            recommendations.append("Implement additional validation checks for low-confidence decisions")
        elif issue["issue_type"] == "Missing Policy Evaluations":
            recommendations.append("Ensure all decisions include comprehensive policy evaluation")
        elif issue["issue_type"] == "Insufficient Reasoning":
            recommendations.append("Require minimum reasoning length and detail for all decisions")
    
    # Based on statistics
    if stats.get("total_decisions", 0) > 100:
        recommendations.append("Consider implementing automated pre-screening for routine requests")
    
    # Default recommendations
    if not recommendations:
        recommendations.extend([
            "Continue current compliance practices",
            "Regular audit trail reviews recommended",
            "Monitor decision quality metrics"
        ])
    
    return recommendations