"""
Test suite for AgenticAccessGovernance API endpoints.
Tests all 8 API endpoints with various scenarios.
"""

import pytest
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi.testclient import TestClient

from src.api.main import app
from src.db.iam_database import IAMDatabase
from src.crew import AccessGovernanceCrew


class TestAccessGovernanceAPI:
    """Test class for all API endpoints."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test client and mocks."""
        self.client = TestClient(app)
        
        # Mock database responses
        self.mock_db = AsyncMock(spec=IAMDatabase)
        self.mock_crew = AsyncMock(spec=AccessGovernanceCrew)
        
        # Override dependencies
        app.dependency_overrides[lambda: self.mock_db] = lambda: self.mock_db
    
    def teardown(self):
        """Clean up after tests."""
        app.dependency_overrides.clear()

    # Test data
    @pytest.fixture
    def sample_request_data(self):
        """Sample access request data for testing."""
        return {
            "user_id": "USR001",
            "system_id": "SYS001",
            "access_level": "read",
            "request_type": "new_access",
            "justification": "Need access for quarterly reporting analysis",
            "required_by_date": (datetime.now() + timedelta(days=7)).isoformat(),
            "is_emergency": False
        }
    
    @pytest.fixture
    def sample_governance_result(self):
        """Sample governance decision result."""
        return {
            "request_id": "REQ123456789",
            "final_decision": "APPROVED",
            "processed_at": datetime.now().isoformat(),
            "workflow_version": "1.0",
            "reasoning": "Low risk request from authorized user for appropriate system access.",
            "risk_analysis": {
                "overall_risk_score": 25,
                "risk_level": "LOW",
                "risk_components": {
                    "user_risk": 20,
                    "system_risk": 30,
                    "access_level_risk": 15,
                    "policy_risk": 10,
                    "sod_risk": 0,
                    "temporal_risk": 5,
                    "anomaly_risk": 0
                }
            },
            "policy_analysis": {
                "overall_decision": "approve",
                "confidence_score": 0.95,
                "violation_reasons": [],
                "regulatory_flags": []
            }
        }

    # Test 1: POST /api/v1/request (Synchronous processing)
    @patch('src.api.main.governance_crew')
    def test_submit_access_request_success(self, mock_crew_global, sample_request_data, sample_governance_result):
        """Test successful synchronous access request processing."""
        # Mock the crew processing
        mock_crew_global.process_access_request = AsyncMock(return_value=sample_governance_result)
        
        response = self.client.post("/api/v1/request", json=sample_request_data)
        
        assert response.status_code == 201
        data = response.json()
        assert "request_id" in data
        assert data["status"] == "completed"
        assert data["decision"] == "APPROVED"
        assert "processing_time" in data
        
        # Verify crew was called
        mock_crew_global.process_access_request.assert_called_once()
    
    @patch('src.api.main.governance_crew')
    def test_submit_access_request_denied(self, mock_crew_global, sample_request_data):
        """Test access request that gets denied."""
        # Mock denied result
        denied_result = {
            "request_id": "REQ123456789",
            "final_decision": "DENIED",
            "processed_at": datetime.now().isoformat(),
            "reasoning": "Policy violation detected."
        }
        mock_crew_global.process_access_request = AsyncMock(return_value=denied_result)
        
        response = self.client.post("/api/v1/request", json=sample_request_data)
        
        assert response.status_code == 200  # Valid response, but denied
        data = response.json()
        assert data["decision"] == "DENIED"
    
    @patch('src.api.main.governance_crew')
    def test_submit_access_request_error(self, mock_crew_global, sample_request_data):
        """Test access request processing error."""
        # Mock error result
        error_result = {
            "request_id": "REQ123456789",
            "final_decision": "ERROR",
            "error": "System error during processing"
        }
        mock_crew_global.process_access_request = AsyncMock(return_value=error_result)
        
        response = self.client.post("/api/v1/request", json=sample_request_data)
        
        assert response.status_code == 500
        data = response.json()
        assert data["decision"] == "ERROR"
    
    def test_submit_access_request_invalid_data(self):
        """Test request with missing required fields."""
        invalid_data = {
            "user_id": "USR001",
            # Missing system_id, access_level, justification
        }
        
        response = self.client.post("/api/v1/request", json=invalid_data)
        
        assert response.status_code == 422  # Validation error

    # Test 2: POST /api/v1/request/async (Asynchronous processing)
    def test_submit_async_access_request_success(self, sample_request_data):
        """Test successful asynchronous access request submission."""
        response = self.client.post("/api/v1/request/async", json=sample_request_data)
        
        assert response.status_code == 202
        data = response.json()
        assert "request_id" in data
        assert data["status"] == "submitted"
        assert "tracking_url" in data
        assert "/api/v1/request/" in data["tracking_url"]
    
    def test_submit_async_access_request_emergency(self, sample_request_data):
        """Test emergency access request handling."""
        sample_request_data["is_emergency"] = True
        
        response = self.client.post("/api/v1/request/async", json=sample_request_data)
        
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "submitted"

    # Test 3: GET /api/v1/request/{request_id} (Get request status)
    def test_get_request_status_background_task(self):
        """Test getting status for background task."""
        # Simulate a background task
        request_id = "REQ123456789"
        from src.api.main import background_tasks
        background_tasks[request_id] = {
            "status": "completed",
            "submitted_at": datetime.now(),
            "processing_completed": datetime.now(),
            "result": {"final_decision": "APPROVED"},
            "decision": "APPROVED"
        }
        
        response = self.client.get(f"/api/v1/request/{request_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == request_id
        assert data["status"] == "completed"
        assert data["decision"] == "APPROVED"
    
    @patch('src.api.main.governance_crew')
    def test_get_request_status_database(self, mock_crew_global):
        """Test getting status from database."""
        request_id = "REQ123456789"
        db_result = {
            "request_id": request_id,
            "final_decision": "APPROVED",
            "processed_at": datetime.now().isoformat()
        }
        
        mock_crew_global.get_request_status = AsyncMock(return_value=db_result)
        
        response = self.client.get(f"/api/v1/request/{request_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == request_id
        assert data["retrieved_from"] == "database"
    
    def test_get_request_status_not_found(self):
        """Test getting status for non-existent request."""
        response = self.client.get("/api/v1/request/NONEXISTENT")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    # Test 4: GET /api/v1/health (Health check)
    def test_health_check_healthy(self):
        """Test health check when system is healthy."""
        with patch('src.api.main.db', new=MagicMock()):
            with patch('src.api.main.governance_crew.db', new=MagicMock()):
                response = self.client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "timestamp" in data
        assert "version" in data
        assert "database_connected" in data
        assert "agents_initialized" in data
    
    def test_health_check_unhealthy(self):
        """Test health check when system has issues."""
        with patch('src.api.main.db', new=None):
            response = self.client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["database_connected"] is False

    # Test 5: GET /api/v1/users (List users)
    @patch('src.api.main.governance_crew')
    def test_list_users_success(self, mock_crew_global):
        """Test successful user listing."""
        mock_users = [
            {"id": "USR001", "name": "John Doe", "email": "john@example.com"},
            {"id": "USR002", "name": "Jane Smith", "email": "jane@example.com"}
        ]
        
        self.mock_db.list_users = AsyncMock(return_value=mock_users)
        
        response = self.client.get("/api/v1/users")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["id"] == "USR001"
    
    @patch('src.api.main.governance_crew')
    def test_list_users_with_pagination(self, mock_crew_global):
        """Test user listing with pagination parameters."""
        self.mock_db.list_users = AsyncMock(return_value=[])
        
        response = self.client.get("/api/v1/users?limit=10&offset=20")
        
        assert response.status_code == 200
        self.mock_db.list_users.assert_called_with(limit=10, offset=20)

    # Test 6: GET /api/v1/users/{user_id}/entitlements (Get user entitlements)
    @patch('src.api.main.governance_crew')
    def test_get_user_entitlements_success(self, mock_crew_global):
        """Test successful retrieval of user entitlements."""
        user_id = "USR001"
        mock_entitlements = [
            {"id": "ENT001", "system_id": "SYS001", "access_level": "read"},
            {"id": "ENT002", "system_id": "SYS002", "access_level": "write"}
        ]
        
        mock_crew_global.get_user_entitlements = AsyncMock(return_value=mock_entitlements)
        
        response = self.client.get(f"/api/v1/users/{user_id}/entitlements")
        
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == user_id
        assert len(data["entitlements"]) == 2
        assert data["total_count"] == 2
    
    @patch('src.api.main.governance_crew')
    def test_get_user_entitlements_not_found(self, mock_crew_global):
        """Test entitlements request for non-existent user."""
        mock_crew_global.get_user_entitlements = AsyncMock(return_value=None)
        
        response = self.client.get("/api/v1/users/NONEXISTENT/entitlements")
        
        assert response.status_code == 404

    # Test 7: GET /api/v1/audit/{request_id} (Get audit trail)
    @patch('src.api.main.governance_crew')
    def test_get_audit_trail_success(self, mock_crew_global):
        """Test successful audit trail retrieval."""
        request_id = "REQ123456789"
        mock_audit_records = [
            {
                "timestamp": datetime.now().isoformat(),
                "agent_name": "Request Intake Agent",
                "action": "validate_request",
                "decision": "validated",
                "reasoning": "Request is complete and valid"
            },
            {
                "timestamp": datetime.now().isoformat(),
                "agent_name": "Policy Validation Agent",
                "action": "check_policies",
                "decision": "compliant",
                "reasoning": "All policies satisfied"
            }
        ]
        
        mock_crew_global.get_audit_trail = AsyncMock(return_value=mock_audit_records)
        
        response = self.client.get(f"/api/v1/audit/{request_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["request_id"] == request_id
        assert len(data["audit_records"]) == 2
        assert data["total_records"] == 2
    
    @patch('src.api.main.governance_crew')
    def test_get_audit_trail_not_found(self, mock_crew_global):
        """Test audit trail request for non-existent request."""
        mock_crew_global.get_audit_trail = AsyncMock(return_value=[])
        
        response = self.client.get("/api/v1/audit/NONEXISTENT")
        
        assert response.status_code == 404

    # Test 8: POST /api/v1/certification/review (Trigger certification review)
    @patch('src.api.main.governance_crew')
    def test_certification_review_success(self, mock_crew_global):
        """Test successful certification review."""
        user_id = "USR001"
        mock_review_result = {
            "user_id": user_id,
            "certification_review": "All certifications are current and compliant. Privacy training expires in 60 days.",
            "reviewed_at": datetime.now().isoformat()
        }
        
        mock_crew_global.review_certifications = AsyncMock(return_value=mock_review_result)
        
        request_data = {"user_id": user_id, "review_type": "full"}
        response = self.client.post("/api/v1/certification/review", json=request_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["user_id"] == user_id
        assert data["review_status"] == "completed"
        assert "certification_summary" in data
        assert "recommendations" in data
    
    @patch('src.api.main.governance_crew')
    def test_certification_review_user_not_found(self, mock_crew_global):
        """Test certification review for non-existent user."""
        mock_review_result = {
            "user_id": "NONEXISTENT",
            "error": "User NONEXISTENT not found",
            "reviewed_at": datetime.now().isoformat()
        }
        
        mock_crew_global.review_certifications = AsyncMock(return_value=mock_review_result)
        
        request_data = {"user_id": "NONEXISTENT", "review_type": "full"}
        response = self.client.post("/api/v1/certification/review", json=request_data)
        
        assert response.status_code == 404
    
    @patch('src.api.main.governance_crew')
    def test_certification_review_system_error(self, mock_crew_global):
        """Test certification review with system error."""
        mock_review_result = {
            "user_id": "USR001",
            "error": "Database connection failed",
            "reviewed_at": datetime.now().isoformat()
        }
        
        mock_crew_global.review_certifications = AsyncMock(return_value=mock_review_result)
        
        request_data = {"user_id": "USR001", "review_type": "full"}
        response = self.client.post("/api/v1/certification/review", json=request_data)
        
        assert response.status_code == 500

    # Additional utility endpoint tests
    def test_get_system_stats(self):
        """Test system statistics endpoint."""
        response = self.client.get("/api/v1/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "requests_processed_today" in data
        assert "active_background_tasks" in data
        assert "version" in data

    # Integration tests
    @patch('src.api.main.governance_crew')
    def test_full_workflow_integration(self, mock_crew_global, sample_request_data, sample_governance_result):
        """Test complete workflow from submission to status check."""
        # Mock the crew processing
        mock_crew_global.process_access_request = AsyncMock(return_value=sample_governance_result)
        mock_crew_global.get_request_status = AsyncMock(return_value=sample_governance_result)
        
        # Submit request
        response = self.client.post("/api/v1/request", json=sample_request_data)
        assert response.status_code == 201
        request_id = response.json()["request_id"]
        
        # Check status
        response = self.client.get(f"/api/v1/request/{request_id}")
        assert response.status_code == 200
        assert response.json()["governance_result"]["final_decision"] == "APPROVED"

    # Error handling tests
    def test_malformed_json_request(self):
        """Test handling of malformed JSON in requests."""
        response = self.client.post(
            "/api/v1/request",
            data="invalid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 422
    
    def test_missing_content_type(self):
        """Test handling of missing content type."""
        response = self.client.post("/api/v1/request", data='{"test": "data"}')
        
        assert response.status_code == 422

    # Security tests
    def test_sql_injection_protection(self):
        """Test protection against SQL injection attempts."""
        malicious_user_id = "USR001'; DROP TABLE users; --"
        
        response = self.client.get(f"/api/v1/users/{malicious_user_id}/entitlements")
        
        # Should handle gracefully, not crash
        assert response.status_code in [404, 500]
    
    def test_xss_protection(self):
        """Test protection against XSS attempts in requests."""
        xss_data = {
            "user_id": "USR001",
            "system_id": "SYS001",
            "access_level": "read",
            "justification": "<script>alert('xss')</script>Need access for reporting"
        }
        
        # Should process without executing script
        response = self.client.post("/api/v1/request/async", json=xss_data)
        assert response.status_code in [202, 422]  # Either accepted or validation error

    # Performance tests
    def test_large_request_payload(self):
        """Test handling of large request payloads."""
        large_justification = "A" * 10000  # 10KB justification
        
        large_data = {
            "user_id": "USR001",
            "system_id": "SYS001",
            "access_level": "read",
            "justification": large_justification
        }
        
        response = self.client.post("/api/v1/request/async", json=large_data)
        
        # Should handle large payloads (might have size limits)
        assert response.status_code in [202, 413]  # Accepted or payload too large

    # CORS tests
    def test_cors_headers(self):
        """Test CORS headers are present."""
        response = self.client.options("/api/v1/health")
        
        assert response.status_code == 200
        # In a real test, you'd check for specific CORS headers


# Pytest configuration and fixtures
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def client():
    """Test client fixture."""
    with TestClient(app) as test_client:
        yield test_client

# Test runner
if __name__ == "__main__":
    pytest.main([__file__, "-v"])