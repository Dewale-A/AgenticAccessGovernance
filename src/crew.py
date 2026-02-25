"""
AccessGovernanceCrew - Main orchestrator for the AI-powered access governance system.
Coordinates six specialized agents to process access requests through a complete governance workflow.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from crewai import Crew, Process
from crewai.project import CrewBase, agent, task, crew

from src.agents.gov_agents import GovernanceAgents
from src.tasks.gov_tasks import GovernanceTasks
from src.db.iam_database import IAMDatabase
from src.config.settings import settings

logger = logging.getLogger(__name__)


@CrewBase
class AccessGovernanceCrew:
    """Main crew class that orchestrates the access governance workflow."""
    
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'
    
    def __init__(self):
        """Initialize the governance crew with agents and database connection."""
        self.db = None
        self.governance_agents = GovernanceAgents()
        self.governance_tasks = GovernanceTasks()
        
    async def initialize(self):
        """Initialize database connection and agents."""
        if not self.db:
            self.db = IAMDatabase()
            await self.db.initialize()
            logger.info("AccessGovernanceCrew initialized with database connection")
    
    @agent
    def request_intake_agent(self):
        """Create the Request Intake Agent."""
        return self.governance_agents.request_intake_agent()
    
    @agent
    def policy_validation_agent(self):
        """Create the Policy Validation Agent."""
        return self.governance_agents.policy_validation_agent()
    
    @agent 
    def risk_scoring_agent(self):
        """Create the Risk Scoring Agent."""
        return self.governance_agents.risk_scoring_agent()
    
    @agent
    def approval_routing_agent(self):
        """Create the Approval Routing Agent."""
        return self.governance_agents.approval_routing_agent()
    
    @agent
    def audit_trail_agent(self):
        """Create the Audit Trail Agent."""
        return self.governance_agents.audit_trail_agent()
    
    @agent
    def certification_review_agent(self):
        """Create the Certification Review Agent."""
        return self.governance_agents.certification_review_agent()
    
    @task
    def request_intake_task(self):
        """Create the request intake task."""
        return self.governance_tasks.request_intake_task()
    
    @task
    def policy_validation_task(self):
        """Create the policy validation task."""
        return self.governance_tasks.policy_validation_task()
    
    @task
    def risk_scoring_task(self):
        """Create the risk scoring task.""" 
        return self.governance_tasks.risk_scoring_task()
    
    @task
    def approval_routing_task(self):
        """Create the approval routing task."""
        return self.governance_tasks.approval_routing_task()
    
    @task
    def audit_trail_task(self):
        """Create the audit trail task."""
        return self.governance_tasks.audit_trail_task()
    
    @task
    def certification_review_task(self):
        """Create the certification review task."""
        return self.governance_tasks.certification_review_task()
    
    @crew
    def crew(self) -> Crew:
        """Create and configure the governance crew."""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
            memory=True,
            embedder={
                "provider": "openai",
                "config": {
                    "model": "text-embedding-3-small"
                }
            }
        )
    
    async def process_access_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an access request through the complete governance workflow.
        
        Args:
            request_data: Access request information
            
        Returns:
            Complete governance decision with reasoning and audit trail
        """
        try:
            # Initialize if not already done
            if not self.db:
                await self.initialize()
            
            logger.info(f"Processing access request {request_data.get('id', 'UNKNOWN')}")
            
            # Prepare inputs for the crew
            inputs = {
                "request_data": json.dumps(request_data),
                "request_id": request_data.get("id", ""),
                "user_id": request_data.get("user_id", ""),
                "system_id": request_data.get("system_id", ""),
                "access_level": request_data.get("access_level", ""),
                "justification": request_data.get("justification", ""),
                "is_emergency": request_data.get("is_emergency", False),
                "timestamp": datetime.now().isoformat()
            }
            
            # Execute the crew workflow
            result = self.crew().kickoff(inputs=inputs)
            
            # Parse and structure the final result
            governance_decision = self._parse_crew_result(result, request_data)
            
            # Store the decision in database
            if self.db:
                await self.db.store_decision(request_data["id"], governance_decision)
            
            logger.info(f"Successfully processed request {request_data.get('id')} with decision: {governance_decision.get('final_decision')}")
            
            return governance_decision
            
        except Exception as e:
            logger.error(f"Error processing access request: {str(e)}")
            return {
                "final_decision": "ERROR",
                "error": str(e),
                "request_id": request_data.get("id", ""),
                "timestamp": datetime.now().isoformat(),
                "reasoning": f"System error during processing: {str(e)}"
            }
    
    def _parse_crew_result(self, result, original_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse and structure the crew execution result into a comprehensive decision.
        
        Args:
            result: Raw crew execution result
            original_request: Original access request data
            
        Returns:
            Structured governance decision
        """
        try:
            # Extract the final output from the crew result
            if hasattr(result, 'raw'):
                decision_text = result.raw
            else:
                decision_text = str(result)
            
            # Try to parse as JSON if possible
            try:
                if decision_text.strip().startswith('{'):
                    parsed_result = json.loads(decision_text)
                    if isinstance(parsed_result, dict):
                        # Add metadata to parsed result
                        parsed_result.update({
                            "request_id": original_request.get("id", ""),
                            "processed_at": datetime.now().isoformat(),
                            "workflow_version": "1.0"
                        })
                        return parsed_result
            except json.JSONDecodeError:
                pass
            
            # If not JSON, extract key information from text
            decision = self._extract_decision_from_text(decision_text)
            
            # Structure the basic response
            governance_decision = {
                "request_id": original_request.get("id", ""),
                "final_decision": decision,
                "processed_at": datetime.now().isoformat(),
                "workflow_version": "1.0",
                "reasoning": decision_text[:1000] + "..." if len(decision_text) > 1000 else decision_text,
                "original_request": original_request
            }
            
            # Add additional context if available
            if "risk" in decision_text.lower():
                governance_decision["risk_factors_mentioned"] = self._extract_risk_factors(decision_text)
            
            if "policy" in decision_text.lower():
                governance_decision["policy_concerns_mentioned"] = True
            
            return governance_decision
            
        except Exception as e:
            logger.error(f"Error parsing crew result: {str(e)}")
            return {
                "request_id": original_request.get("id", ""),
                "final_decision": "ERROR",
                "processed_at": datetime.now().isoformat(),
                "error": f"Result parsing error: {str(e)}",
                "raw_output": str(result)[:500]
            }
    
    def _extract_decision_from_text(self, text: str) -> str:
        """Extract the final decision from text output."""
        text_lower = text.lower()
        
        # Look for explicit decision keywords
        if "approved" in text_lower and "not approved" not in text_lower:
            return "APPROVED"
        elif "denied" in text_lower or "deny" in text_lower:
            return "DENIED"
        elif "escalated" in text_lower or "escalate" in text_lower:
            return "ESCALATED"
        elif "error" in text_lower or "failed" in text_lower:
            return "ERROR"
        else:
            # Default to escalation for uncertain cases
            return "ESCALATED"
    
    def _extract_risk_factors(self, text: str) -> List[str]:
        """Extract mentioned risk factors from the text."""
        risk_factors = []
        text_lower = text.lower()
        
        # Common risk factor patterns
        risk_patterns = [
            "high risk", "low risk", "medium risk", "critical risk",
            "policy violation", "regulatory concern", "sod conflict",
            "certification missing", "background check", "emergency access",
            "cross-department", "privileged access"
        ]
        
        for pattern in risk_patterns:
            if pattern in text_lower:
                risk_factors.append(pattern.title())
        
        return risk_factors[:5]  # Limit to top 5 factors
    
    async def get_request_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the current status and decision for a request.
        
        Args:
            request_id: Access request identifier
            
        Returns:
            Request status and decision information
        """
        if not self.db:
            await self.initialize()
        
        return await self.db.get_request_status(request_id)
    
    async def get_user_entitlements(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get current entitlements for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of current user entitlements
        """
        if not self.db:
            await self.initialize()
        
        return await self.db.get_user_entitlements(user_id)
    
    async def get_audit_trail(self, request_id: str) -> List[Dict[str, Any]]:
        """
        Get the complete audit trail for a request.
        
        Args:
            request_id: Access request identifier
            
        Returns:
            List of audit records for the request
        """
        if not self.db:
            await self.initialize()
        
        return await self.db.get_audit_trail(request_id)
    
    async def review_certifications(self, user_id: str) -> Dict[str, Any]:
        """
        Review certification status for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Certification review results
        """
        try:
            if not self.db:
                await self.initialize()
            
            # Get user data
            user_data = await self.db.get_user(user_id)
            if not user_data:
                return {"error": f"User {user_id} not found"}
            
            # Create a simple certification review task
            inputs = {
                "user_data": json.dumps(user_data),
                "user_id": user_id,
                "review_type": "certification_status"
            }
            
            # Use just the certification review agent
            cert_agent = self.certification_review_agent()
            cert_task = self.certification_review_task()
            
            # Create a mini-crew for certification review
            cert_crew = Crew(
                agents=[cert_agent],
                tasks=[cert_task],
                verbose=True
            )
            
            result = cert_crew.kickoff(inputs=inputs)
            
            return {
                "user_id": user_id,
                "certification_review": str(result),
                "reviewed_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error reviewing certifications for {user_id}: {str(e)}")
            return {
                "user_id": user_id,
                "error": str(e),
                "reviewed_at": datetime.now().isoformat()
            }

# Global instance for the API
governance_crew = AccessGovernanceCrew()