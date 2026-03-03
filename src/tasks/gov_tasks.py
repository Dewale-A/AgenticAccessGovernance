"""
Governance Tasks - Task definitions for the six-agent access governance workflow.
Each task represents a specific step in the comprehensive governance process.
"""

import logging
from typing import List

from crewai import Task
from src.config.settings import settings

logger = logging.getLogger(__name__)


class GovernanceTasks:
    """Factory class for creating governance workflow tasks."""
    
    def __init__(self):
        """Initialize the tasks factory."""
        pass
    
    def request_intake_task(self) -> Task:
        """
        Task 1: Request Intake and Validation
        
        Processes incoming access requests, validates completeness, and gathers context.
        """
        return Task(
            description="""Process the incoming access request and gather comprehensive context:

            1. **Request Validation**:
               - Validate all required fields are present and complete
               - Verify business justification is clear and sufficient
               - Check if this is an emergency or time-sensitive request
               - Identify any missing information that could affect processing

            2. **Context Gathering**:
               - Look up detailed user information (role, department, tenure, certifications)
               - Retrieve target system information (sensitivity, regulatory requirements)
               - Get current user entitlements and access history
               - Identify the user's manager and organizational context

            3. **Request Classification**:
               - Classify the request type (new access, modification, emergency, etc.)
               - Assess the business urgency and required timeline
               - Flag any obvious red flags or concerns for downstream processing
               - Determine if this appears to be a routine or exceptional request

            4. **Initial Assessment**:
               - Perform initial completeness and reasonableness checks
               - Identify any obvious policy or regulatory concerns
               - Note any special handling requirements
               - Prepare structured data package for the next agent

            Input: {request_data}
            Request ID: {request_id}
            
            Provide a comprehensive intake report with all gathered context and initial observations.""",
            expected_output="""A comprehensive request intake report containing:
            - Request validation status (complete/incomplete/needs clarification)
            - Complete user profile with role, department, tenure, and certification status
            - Target system details with sensitivity and regulatory classification
            - Current user entitlements and access pattern history
            - Request classification and urgency assessment
            - Initial red flags or concerns identified
            - Structured data package for policy validation
            - Recommendations for any special handling requirements
            
            Format: Structured JSON report with clear sections for each component."""
        )
    
    def policy_validation_task(self) -> Task:
        """
        Task 2: Policy Compliance Validation
        
        Evaluates the request against all applicable policies and regulatory requirements.
        """
        return Task(
            description="""Conduct comprehensive policy compliance evaluation using the intake report:

            1. **RBAC Rule Validation**:
               - Check if the user's role is authorized for the requested system access
               - Verify the requested access level is appropriate for the user's role
               - Validate any role-specific conditions or requirements are met
               - Review exceptions and special circumstances

            2. **Departmental Policy Compliance**:
               - Evaluate departmental access policies for the user's department
               - Check cross-departmental access policies if applicable
               - Review any department-specific approval requirements
               - Assess business-hours vs after-hours request policies

            3. **Regulatory Constraint Validation**:
               - Validate compliance with OSFI guidelines for financial institutions
               - Check PIPEDA privacy requirements for personal data access
               - Verify SOX compliance for financial reporting systems
               - Assess IIROC requirements for investment industry systems
               - Review SR 11-7 model risk management constraints

            4. **Sensitivity Tier Assessment**:
               - Validate user's authorization for the system's sensitivity tier
               - Check data classification access requirements
               - Review confidential and restricted data access policies
               - Assess additional controls required for high-sensitivity systems

            5. **Policy Decision**:
               - Determine overall policy compliance status
               - Identify any policy violations or concerns
               - Flag regulatory compliance issues
               - Provide detailed reasoning for the policy assessment

            Use the policy_checker tool with the intake data to perform this analysis.
            
            Based on the intake report, provide a comprehensive policy compliance assessment.""",
            expected_output="""A detailed policy compliance report containing:
            - Overall policy compliance status (compliant/violation/requires_review)
            - RBAC rule evaluation results with specific rule references
            - Departmental policy assessment and any cross-department concerns
            - Regulatory compliance analysis for each applicable regulation
            - Sensitivity tier access validation results
            - List of any policy violations or concerns with severity levels
            - Regulatory flags requiring attention or additional approvals
            - Recommended conditions or constraints for approval
            - Detailed reasoning for each policy decision
            
            Format: Structured analysis with clear compliance/violation indicators."""
        )
    
    def risk_scoring_task(self) -> Task:
        """
        Task 3: Comprehensive Risk Assessment
        
        Assigns risk scores based on multiple factors and provides detailed risk analysis.
        """
        return Task(
            description="""Conduct comprehensive risk assessment using intake and policy analysis:

            1. **User Risk Assessment**:
               - Evaluate user tenure, status, and access history
               - Assess failed login attempts and anomalous behavior
               - Review user's current risk profile and previous incidents
               - Consider role appropriateness and organizational fit

            2. **System Risk Assessment**:
               - Analyze target system's data sensitivity and criticality
               - Assess regulatory impact and compliance requirements
               - Review system's business importance and exposure
               - Evaluate technical security controls and monitoring

            3. **Access Level Risk Assessment**:
               - Evaluate the risk level of the requested access (read/write/admin/execute)
               - Consider the combination of user role and access level
               - Assess potential for privilege escalation or misuse
               - Review appropriateness of access level for business justification

            4. **Contextual Risk Assessment**:
               - Analyze timing factors (emergency requests, after-hours, etc.)
               - Review business justification strength and clarity
               - Assess cross-departmental access risks
               - Consider temporary vs permanent access implications

            5. **Policy and Regulatory Risk**:
               - Incorporate policy violations from previous analysis
               - Assess regulatory compliance risk and potential violations
               - Review segregation of duties conflicts and implications
               - Consider audit and examination risk factors

            6. **Integrated Risk Scoring**:
               - Calculate composite risk score (1-100 scale)
               - Assign risk level (LOW/MEDIUM/HIGH/CRITICAL)
               - Provide risk factor breakdown and relative weights
               - Generate risk-based recommendations

            Use the risk_scorer and sod_validator tools for comprehensive analysis.
            
            Based on intake and policy reports, provide detailed risk assessment.""",
            expected_output="""A comprehensive risk assessment report containing:
            - Overall risk score (1-100) with clear risk level designation
            - Detailed risk component breakdown (user, system, access, contextual, policy)
            - Risk factor identification with relative impact assessment
            - Segregation of duties analysis and conflict identification
            - Risk-based recommendations for approval, conditions, or denial
            - Monitoring and control recommendations based on risk level
            - Comparative risk analysis against organizational thresholds
            - Mitigation strategies for identified high-risk factors
            
            Format: Quantitative risk assessment with detailed qualitative analysis."""
        )
    
    def approval_routing_task(self) -> Task:
        """
        Task 4: Approval Routing Decision
        
        Determines approval routing based on risk assessment and organizational policies.
        """
        return Task(
            description="""Make approval routing decision based on comprehensive analysis:

            1. **Risk-Based Routing Analysis**:
               - Apply organizational risk thresholds (Low <{low_risk_threshold}, High >{high_risk_threshold})
               - Determine if request qualifies for auto-approval (typically <{low_risk_threshold})
               - Assess if request requires escalation (typically >{high_risk_threshold})
               - Consider middle-tier recommendations for standard approval process

            2. **Approval Level Determination**:
               - Map risk level to required approval authority (Manager/Senior Manager/Director/CISO)
               - Consider policy requirements for specific approval levels
               - Assess regulatory requirements for certain types of access
               - Determine if multiple approvals are required

            3. **Workflow Routing Decision**:
               - AUTO-APPROVE: Low risk, policy compliant, routine access requests
               - STANDARD APPROVAL: Medium risk requiring manager approval with documentation
               - ESCALATED APPROVAL: High risk requiring senior management and compliance review
               - DENY: Policy violations, critical risk, or regulatory non-compliance
               - CONDITIONAL APPROVAL: Medium-high risk with specific conditions and monitoring

            4. **Conditional Requirements**:
               - Define any conditions that must be met for approval
               - Specify monitoring requirements and review frequencies
               - Set access time limits for temporary or high-risk access
               - Require additional documentation or justification

            5. **Stakeholder Notification**:
               - Identify all required approvers and stakeholders
               - Determine notification requirements for compliance and audit
               - Specify escalation procedures and timelines
               - Plan communication strategy for all parties

            Based on all previous analyses, make the final routing decision with clear reasoning.
            
            Risk Thresholds: Low <{low_risk_threshold}, High >{high_risk_threshold}""".format(
                low_risk_threshold=settings.low_risk_threshold,
                high_risk_threshold=settings.high_risk_threshold
            ),
            expected_output="""A comprehensive approval routing decision containing:
            - Final routing decision (AUTO_APPROVE/STANDARD_APPROVAL/ESCALATED_APPROVAL/DENY/CONDITIONAL)
            - Detailed reasoning for the routing decision with risk and policy factors
            - Required approval authority level and specific approvers if known
            - Any conditions or constraints that must be applied to the approval
            - Monitoring and review requirements with specific timelines
            - Stakeholder notification requirements and communication plan
            - Expected processing timeline and any urgency considerations
            - Clear next steps for request processing and follow-up actions
            
            Format: Structured decision with clear action items and requirements."""
        )
    
    def audit_trail_task(self) -> Task:
        """
        Task 5: Comprehensive Audit Trail Creation
        
        Creates complete audit documentation for the governance decision.
        """
        return Task(
            description="""Create comprehensive audit trail for the governance decision:

            1. **Decision Documentation**:
               - Record the final governance decision with complete reasoning
               - Document all agents involved and their specific contributions
               - Log all tools used and data sources consulted
               - Record timestamps for each stage of the workflow

            2. **Evidence Collection**:
               - Compile all policy rules and regulations that were evaluated
               - Document risk factors identified and their relative weights
               - Record any exceptions or special circumstances considered
               - Archive all supporting documentation and references

            3. **Reasoning Trail**:
               - Document the logical flow from request to decision
               - Record how each factor contributed to the final decision
               - Explain any conflicts between different evaluation criteria
               - Document the basis for any judgment calls or interpretations

            4. **Regulatory Compliance Documentation**:
               - Ensure all regulatory requirements are properly documented
               - Record compliance with organizational audit standards
               - Document any regulatory flags or concerns identified
               - Prepare documentation for potential regulatory examination

            5. **Traceability and Accountability**:
               - Create clear links between inputs, analysis, and outputs
               - Document all decision makers and their specific roles
               - Record confidence levels and uncertainty factors
               - Establish clear accountability for the governance decision

            6. **Audit Log Creation**:
               - Generate formal audit record with all required fields
               - Ensure log meets organizational and regulatory standards
               - Create searchable and reportable audit entries
               - Establish proper retention and archival procedures

            Use the audit_logger tool to create formal audit records.
            
            Based on all previous analyses and decisions, create comprehensive audit documentation.""",
            expected_output="""A complete audit trail package containing:
            - Formal audit record with all required regulatory fields
            - Comprehensive decision documentation with complete reasoning chain
            - Evidence package with all supporting documents and data sources
            - Regulatory compliance checklist with specific requirement validation
            - Traceability matrix linking inputs to analysis to decision
            - Risk assessment documentation with detailed factor analysis
            - Policy evaluation record with specific rule references
            - Stakeholder accountability record with roles and responsibilities
            - Searchable audit log entries formatted for reporting and analysis
            - Retention and archival instructions for regulatory compliance
            
            Format: Formal audit documentation meeting financial services regulatory standards."""
        )
    
    def certification_review_task(self) -> Task:
        """
        Task 6: Certification and Training Validation
        
        Validates training certifications and compliance requirements.
        """
        return Task(
            description="""Validate user certifications and training requirements:

            1. **Required Certification Validation**:
               - Check privacy training certification status and expiration
               - Validate model risk management training for relevant systems
               - Verify background check currency and completeness
               - Review SOX certification for financial reporting system access
               - Assess any role-specific or system-specific training requirements

            2. **Regulatory Training Compliance**:
               - Validate OSFI-required training for financial institution roles
               - Check PIPEDA privacy training for personal data access
               - Review IIROC training for investment industry systems
               - Assess any other regulator-specific training requirements
               - Verify continuing education and renewal requirements

            3. **Certification Currency Assessment**:
               - Check if all certifications are current and not expired
               - Identify certifications that are nearing expiration (within 30 days)
               - Flag any expired certifications that block access approval
               - Review renewal schedules and upcoming requirements

            4. **Access-Specific Training Requirements**:
               - Map requested access to specific training requirements
               - Verify user has completed all necessary training for the target system
               - Check for any additional training required before access grant
               - Assess ongoing training requirements for maintained access

            5. **Certification Impact on Decision**:
               - Determine if certification status affects approval decision
               - Identify any training that must be completed before access grant
               - Flag any certification issues that require escalation
               - Recommend any additional training or certification actions

            6. **Training Compliance Record**:
               - Document all certification checks performed
               - Record current status of each required certification
               - Note any compliance gaps or concerns
               - Provide recommendations for certification remediation

            Use the certification_checker tool for comprehensive validation.
            
            Based on user data and access requirements, validate all certification requirements.""",
            expected_output="""A comprehensive certification compliance report containing:
            - Complete certification status summary with current/expired/missing indicators
            - Detailed validation of each required certification with expiration dates
            - Regulatory training compliance assessment with specific requirement mapping
            - Access-specific training requirement validation and gap analysis
            - Certification impact assessment on the approval decision
            - Required actions for certification compliance (training, renewal, etc.)
            - Risk assessment of any certification gaps or compliance issues
            - Recommendations for certification remediation and ongoing compliance
            - Training schedule and renewal calendar for ongoing compliance
            - Documentation supporting certification-related decision factors
            
            Format: Structured compliance report with clear status indicators and action items."""
        )
    
    def get_all_tasks(self) -> List[Task]:
        """Return all governance tasks as a list in execution order."""
        return [
            self.request_intake_task(),
            self.policy_validation_task(),
            self.risk_scoring_task(),
            self.approval_routing_task(),
            self.audit_trail_task(),
            self.certification_review_task()
        ]