"""
Pytest configuration and fixtures for testing.
"""
import os
import sys
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import Mock, AsyncMock
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi.testclient import TestClient
from app.main import app

# Test configuration
os.environ["TESTING"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["ANTHROPIC_API_KEY"] = "test-api-key"
os.environ["CLAUDE_MODEL"] = "claude-4.0-sonnet"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def client() -> Generator:
    """Create a test client for the FastAPI app."""
    with TestClient(app) as c:
        yield c

@pytest.fixture
def mock_supabase():
    """Mock Supabase client."""
    mock = Mock()
    
    # Mock table methods
    mock.table.return_value.select.return_value.execute.return_value.data = []
    mock.table.return_value.insert.return_value.execute.return_value.data = [{"id": "test-id"}]
    mock.table.return_value.update.return_value.eq.return_value.execute.return_value.data = [{"id": "test-id"}]
    
    # Mock auth
    mock.auth.sign_in_with_password.return_value.user = Mock(id="test-user-id")
    
    return mock

@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock = AsyncMock()
    mock.get.return_value = None
    mock.set.return_value = True
    mock.delete.return_value = True
    mock.exists.return_value = False
    return mock

@pytest.fixture
def mock_claude():
    """Mock Claude client."""
    mock = Mock()
    mock.messages.create.return_value = Mock(
        content=[Mock(text="Test AI response")]
    )
    return mock

@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability for testing."""
    return {
        "title": "SQL Injection",
        "description": "User input concatenated in SQL query",
        "severity": "critical",
        "category": "injection",
        "vulnerability_type": "sql injection",
        "file_path": "test.py",
        "line_start": 10,
        "line_end": 10,
        "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "scanner": "semgrep",
        "rule_id": "python.sql.injection",
        "confidence": "HIGH"
    }

@pytest.fixture
def sample_scan_results():
    """Sample scan results for testing."""
    return [
        {
            "title": "SQL Injection",
            "severity": "critical",
            "category": "injection",
            "vulnerability_type": "sql injection",
            "file_path": "app.py",
            "line_start": 25
        },
        {
            "title": "Hardcoded Password",
            "severity": "high",
            "category": "secrets",
            "vulnerability_type": "hardcoded credential",
            "file_path": "config.py",
            "line_start": 5
        },
        {
            "title": "Cross-site Scripting",
            "severity": "medium",
            "category": "injection",
            "vulnerability_type": "xss",
            "file_path": "templates/index.html",
            "line_start": 100
        }
    ]

@pytest.fixture
def auth_headers():
    """Authorization headers for testing."""
    return {"Authorization": "Bearer test-token"}

@pytest.fixture
async def test_user():
    """Test user data."""
    return {
        "id": "test-user-id",
        "email": "test@example.com",
        "created_at": datetime.utcnow().isoformat()
    }

@pytest.fixture
async def test_project():
    """Test project data."""
    return {
        "id": "test-project-id",
        "name": "Test Project",
        "description": "Test project for unit tests",
        "language": "python",
        "user_id": "test-user-id",
        "created_at": datetime.utcnow().isoformat()
    }

@pytest.fixture
async def test_scan():
    """Test scan data."""
    return {
        "id": "test-scan-id",
        "project_id": "test-project-id",
        "user_id": "test-user-id",
        "scan_type": "full",
        "status": "pending",
        "created_at": datetime.utcnow().isoformat()
    }