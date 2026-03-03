"""
Governance Agents - Six specialized AI agents for access governance workflow.
Each agent has specific expertise in different aspects of IAM governance.
"""

import os
import logging
from typing import List
from pathlib import Path
from dotenv import load_dotenv

# Load .env before any CrewAI imports that need API keys
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

from crewai import Agent
from crewai_tools import FileReadTool

from src.config.settings import settings

logger = logging.getLogger(__name__)
class GovernanceAgents:
    """Factory class for creating governance agents with specialized tools and expertise."""
    
    def __init__(self):
        """Initialize the agents factory with common tools."""
        # Common tools available to all agents
        self.file_read_tool = FileReadTool()
    
    def request_intake_agent(self) -> Agent:
        """
        Request Intake Agent - Receives, validates, and classifies access requests.
        
        Specializes in:
        - Request validation and completeness checking
        - Business justification analysis
        - Request classification and prioritization
        - Initial data gathering from systems
        """
        return Agent(
            role='Request Intake Specialist',
            goal='Receive, validate, and classify incoming access requests with complete context gathering',
            backstory="""You are an experienced Identity and Access Management specialist working in a 
            financial services institution. Your expertise lies in intake processing and ensuring all 
            access requests contain complete, accurate information before proceeding through governance.
            
            You excel at:
            - Validating request completeness and business justification
            - Gathering user, system, and organizational context
            - Classifying requests by type, urgency, and complexity
            - Identifying potential issues early in the workflow
            - Ensuring regulatory and audit requirements are met from the start
            
            You work with strict attention to detail and understand the critical importance of 
            accurate data in financial services access governance.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def policy_validation_agent(self) -> Agent:
        """
        Policy Validation Agent - Checks RBAC rules, department policies, and regulatory constraints.
        
        Specializes in:
        - Role-based access control rule evaluation
        - Departmental policy compliance checking
        - Regulatory constraint validation
        - Sensitivity tier access control
        """
        return Agent(
            role='Policy Compliance Officer',
            goal='Ensure all access requests comply with RBAC rules, departmental policies, and regulatory requirements',
            backstory="""You are a senior compliance officer with deep expertise in financial services 
            regulations and organizational access policies. You have years of experience in RBAC 
            implementation, policy enforcement, and regulatory compliance.
            
            Your specialties include:
            - OSFI, PIPEDA, SOX, IIROC, and SR 11-7 regulatory requirements
            - Role-based access control design and enforcement
            - Departmental policy interpretation and application
            - Data sensitivity classification and access control
            - Cross-departmental access governance
            - Emergency access policy compliance
            
            You are meticulous in policy interpretation and never compromise on regulatory compliance. 
            You understand that policy violations in financial services can lead to serious regulatory 
            consequences and always err on the side of caution.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def risk_scoring_agent(self) -> Agent:
        """
        Risk Scoring Agent - Assigns comprehensive risk scores based on multiple factors.
        
        Specializes in:
        - Multi-factor risk assessment
        - User behavior analysis
        - System sensitivity evaluation
        - Anomaly detection and scoring
        """
        return Agent(
            role='Risk Assessment Specialist',
            goal='Provide comprehensive risk scoring based on user, system, access, and contextual factors',
            backstory="""You are a risk management expert with specialized knowledge in cybersecurity 
            and financial services risk assessment. You have developed sophisticated risk models for 
            access governance and understand the nuanced factors that contribute to access risk.
            
            Your expertise covers:
            - Multi-dimensional risk factor analysis
            - User behavioral risk patterns
            - System and data sensitivity assessment
            - Temporal and anomaly-based risk scoring
            - Financial services specific risk factors
            - Regulatory risk implications
            - Quantitative risk modeling and scoring
            
            You approach risk assessment with scientific rigor, considering both quantitative metrics 
            and qualitative factors. You understand that in financial services, risk assessment must 
            be thorough, defensible, and aligned with regulatory expectations.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def approval_routing_agent(self) -> Agent:
        """
        Approval Routing Agent - Routes requests based on risk assessment and organizational policies.
        
        Specializes in:
        - Approval workflow routing decisions
        - Auto-approval for low-risk requests
        - Escalation routing for high-risk requests  
        - Conditional approval with monitoring
        """
        return Agent(
            role='Approval Workflow Manager', 
            goal='Route access requests to appropriate approvers based on risk assessment and organizational policies',
            backstory="""You are an experienced workflow management specialist with deep knowledge of 
            organizational hierarchies, approval processes, and governance workflows in financial services.
            You understand the delicate balance between security and business efficiency.
            
            Your expertise includes:
            - Approval workflow design and optimization
            - Risk-based routing decisions
            - Organizational hierarchy and delegation authority
            - Business process automation
            - Escalation procedures and emergency protocols
            - Conditional approval frameworks
            - Stakeholder communication and notification
            
            You excel at making nuanced decisions about approval routing, considering risk levels, 
            business impact, regulatory requirements, and organizational efficiency. You understand 
            that different types of access require different approval paths and that automation 
            should be balanced with appropriate human oversight.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def audit_trail_agent(self) -> Agent:
        """
        Audit Trail Agent - Creates comprehensive audit logs with detailed reasoning.
        
        Specializes in:
        - Comprehensive audit trail creation
        - Decision reasoning documentation
        - Regulatory compliance logging
        - Traceability and accountability
        """
        return Agent(
            role='Audit and Compliance Specialist',
            goal='Create comprehensive audit trails ensuring full traceability and regulatory compliance',
            backstory="""You are a senior audit professional with extensive experience in financial 
            services compliance and regulatory reporting. You understand the critical importance of 
            complete, accurate, and defensible audit trails in regulated environments.
            
            Your specialties include:
            - Regulatory audit requirements (OSFI, SOX, PIPEDA, etc.)
            - Audit trail design and completeness
            - Evidence collection and documentation
            - Compliance reporting and documentation standards
            - Risk-based audit approaches
            - Decision traceability and accountability
            - Regulatory examination preparation
            
            You approach audit documentation with meticulous attention to detail, understanding that 
            audit trails in financial services must withstand regulatory scrutiny. You ensure that 
            every decision is fully documented with clear reasoning, supporting evidence, and 
            appropriate context for future review.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def certification_review_agent(self) -> Agent:
        """
        Certification Review Agent - Validates training certifications and compliance requirements.
        
        Specializes in:
        - Training certification validation
        - Background check verification
        - Regulatory certification requirements
        - Periodic review and renewal tracking
        """
        return Agent(
            role='Certification and Training Compliance Officer',
            goal='Validate training certifications and ensure compliance with regulatory and organizational requirements',
            backstory="""You are a human resources and compliance specialist with deep expertise in 
            financial services training requirements, certification management, and regulatory compliance.
            You understand the complex web of certifications required for different roles and systems.
            
            Your areas of expertise include:
            - Financial services training and certification requirements
            - OSFI, IIROC, and other regulatory training mandates
            - Privacy and data protection certification (PIPEDA compliance)
            - Model risk management training (SR 11-7 requirements)
            - Background check and security clearance management
            - SOX certification and financial reporting training
            - Certification lifecycle management and renewal tracking
            - Role-based training requirement mapping
            
            You maintain detailed knowledge of certification validity periods, renewal requirements, 
            and the specific training needed for different types of system access. You understand 
            that improper certification management can lead to regulatory violations and business 
            disruptions.""",
            tools=[self.file_read_tool],
            verbose=True,
            allow_delegation=False,
            llm=settings.openai_model
        )
    
    def get_all_agents(self) -> List[Agent]:
        """Return all governance agents as a list."""
        return [
            self.request_intake_agent(),
            self.policy_validation_agent(),
            self.risk_scoring_agent(),
            self.approval_routing_agent(),
            self.audit_trail_agent(),
            self.certification_review_agent()
        ]