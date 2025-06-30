"""
Tests for API endpoints.
"""
import pytest
from unittest.mock import patch, Mock
import json

class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_root_endpoint(self, client):
        """Test root endpoint."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Codebase Scanner API"
        assert data["version"] == "1.0.0"
    
    def test_health_endpoint(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "codebase-scanner-api"
    
    def test_api_test_endpoint(self, client):
        """Test API test endpoint."""
        response = client.get("/api/test")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "environment" in data

class TestAuthEndpoints:
    """Test authentication endpoints."""
    
    @patch('src.database.get_supabase_client')
    def test_register_success(self, mock_supabase, client):
        """Test successful user registration."""
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []
        mock_supabase.return_value.table.return_value.insert.return_value.execute.return_value.data = [{
            "id": "new-user-id",
            "email": "test@example.com",
            "created_at": "2024-01-01T00:00:00"
        }]
        
        response = client.post("/api/auth/register", json={
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["email"] == "test@example.com"
        assert "access_token" in data
    
    @patch('src.database.get_supabase_client')
    def test_register_duplicate_email(self, mock_supabase, client):
        """Test registration with duplicate email."""
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
            {"id": "existing-user"}
        ]
        
        response = client.post("/api/auth/register", json={
            "email": "existing@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User"
        })
        
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]
    
    def test_demo_token_generation(self, client):
        """Test demo token generation."""
        response = client.post("/api/auth/demo-token")
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "Demo token created" in data["message"]

class TestScanEndpoints:
    """Test scan-related endpoints."""
    
    @patch('src.database.get_supabase_client')
    @patch('app.tasks.scan_tasks.process_scan.delay')
    def test_create_scan(self, mock_task, mock_supabase, client, auth_headers):
        """Test scan creation."""
        # Mock project verification
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value.data = {
            "id": "project-id",
            "name": "Test Project"
        }
        
        # Mock scan creation
        mock_supabase.return_value.table.return_value.insert.return_value.execute.return_value.data = [{
            "id": "scan-id",
            "status": "pending"
        }]
        
        # Mock task
        mock_task.return_value.id = "task-id"
        
        with open("test_file.py", "w") as f:
            f.write("print('test')")
        
        try:
            with open("test_file.py", "rb") as f:
                response = client.post(
                    "/api/scans",
                    headers=auth_headers,
                    data={
                        "project_id": "project-id",
                        "scan_type": "quick"
                    },
                    files={"file": ("test.py", f, "text/x-python")}
                )
            
            assert response.status_code in [200, 201]
            data = response.json()
            assert "scan_id" in data
            assert data["status"] == "processing"
            
        finally:
            import os
            if os.path.exists("test_file.py"):
                os.remove("test_file.py")
    
    @patch('src.database.get_supabase_client')
    def test_get_scan_results(self, mock_supabase, client, auth_headers):
        """Test retrieving scan results."""
        # Mock scan data
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.single.return_value.execute.return_value.data = {
            "id": "scan-id",
            "status": "completed",
            "total_findings": 5
        }
        
        # Mock scan results
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.execute.return_value.data = [
            {"severity": "high", "title": "SQL Injection"},
            {"severity": "medium", "title": "XSS"}
        ]
        
        response = client.get("/api/scans/scan-id/results", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "scan" in data
        assert "results" in data
        assert len(data["results"]) == 2

class TestProjectEndpoints:
    """Test project management endpoints."""
    
    @patch('src.database.get_supabase_client')
    def test_create_project(self, mock_supabase, client, auth_headers):
        """Test project creation."""
        mock_supabase.return_value.table.return_value.insert.return_value.execute.return_value.data = [{
            "id": "new-project-id",
            "name": "New Project",
            "language": "python"
        }]
        
        response = client.post("/api/projects", 
            headers=auth_headers,
            json={
                "name": "New Project",
                "description": "Test project",
                "language": "python"
            }
        )
        
        assert response.status_code in [200, 201]
        data = response.json()
        assert data["name"] == "New Project"
        assert data["language"] == "python"
    
    @patch('src.database.get_supabase_client')
    def test_list_projects(self, mock_supabase, client, auth_headers):
        """Test listing user projects."""
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.order.return_value.execute.return_value.data = [
            {"id": "project-1", "name": "Project 1"},
            {"id": "project-2", "name": "Project 2"}
        ]
        
        response = client.get("/api/projects", headers=auth_headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["name"] == "Project 1"

class TestExportEndpoints:
    """Test export functionality endpoints."""
    
    @patch('src.database.get_supabase_client')
    @patch('app.services.export_service.ExportService')
    def test_export_scan_pdf(self, mock_export, mock_supabase, client, auth_headers):
        """Test PDF export of scan results."""
        # Mock scan ownership check
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.eq.return_value.single.return_value.execute.return_value.data = {
            "id": "scan-id",
            "projects": {"name": "Test Project"}
        }
        
        # Mock export service
        mock_export.return_value.export_scan_results.return_value = b"PDF content"
        
        response = client.get(
            "/api/export/scan/scan-id?format=pdf",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "attachment" in response.headers["content-disposition"]