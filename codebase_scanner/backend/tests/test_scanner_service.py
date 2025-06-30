"""
Tests for scanner service functionality.
"""
import pytest
from unittest.mock import Mock, AsyncMock, patch
import tempfile
import os
from app.services.scanner_service import ScannerService, ScanStatus

class TestScannerService:
    """Test main scanner service."""
    
    @pytest.fixture
    async def scanner_service(self, mock_supabase):
        """Create scanner service instance."""
        with patch('app.services.scanner_service.db'):
            service = ScannerService()
            service.supabase_client = mock_supabase
            service.scanners = {
                "semgrep": AsyncMock(),
                "bandit": AsyncMock()
            }
            service.file_processor = AsyncMock()
            service.result_processor = AsyncMock()
            return service
    
    @pytest.mark.asyncio
    async def test_scan_file_success(self, scanner_service):
        """Test successful file scan."""
        scan_id = "test-scan-id"
        
        # Mock file processing
        scanner_service.file_processor.process_file.return_value = "/tmp/extracted"
        
        # Mock scanner results
        scanner_service.scanners["semgrep"].scan.return_value = [
            {"title": "SQL Injection", "severity": "high"}
        ]
        scanner_service.scanners["bandit"].scan.return_value = [
            {"title": "Hardcoded Password", "severity": "critical"}
        ]
        
        # Mock result processing
        scanner_service.result_processor.process_results.return_value = [
            {"title": "SQL Injection", "severity": "high", "fingerprint": "abc123"},
            {"title": "Hardcoded Password", "severity": "critical", "fingerprint": "def456"}
        ]
        
        # Run scan
        await scanner_service.scan_file(
            scan_id=scan_id,
            file_data=b"test content",
            filename="test.py",
            scan_config={"scanners": ["semgrep", "bandit"]}
        )
        
        # Verify file processing
        scanner_service.file_processor.process_file.assert_called_once()
        
        # Verify scanners were called
        assert scanner_service.scanners["semgrep"].scan.called
        assert scanner_service.scanners["bandit"].scan.called
        
        # Verify results were processed
        scanner_service.result_processor.process_results.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_scan_file_with_error(self, scanner_service):
        """Test scan with scanner error."""
        scan_id = "test-scan-id"
        
        # Mock file processing
        scanner_service.file_processor.process_file.return_value = "/tmp/extracted"
        
        # Mock scanner error
        scanner_service.scanners["semgrep"].scan.side_effect = Exception("Scanner failed")
        
        # Run scan - should not raise exception
        await scanner_service.scan_file(
            scan_id=scan_id,
            file_data=b"test content",
            filename="test.py",
            scan_config={"scanners": ["semgrep"]}
        )
        
        # Verify error was handled gracefully
        assert True  # Should complete without raising
    
    def test_calculate_summary(self, scanner_service):
        """Test summary calculation."""
        results = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "low"}
        ]
        
        summary = scanner_service._calculate_summary(results)
        
        assert summary["total"] == 6
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["medium"] == 2
        assert summary["low"] == 1
        assert summary["info"] == 0
    
    def test_get_enabled_scanners_default(self, scanner_service):
        """Test getting enabled scanners with defaults."""
        config = {}
        scanners = scanner_service._get_enabled_scanners(config)
        
        # Should return default scanners
        assert len(scanners) > 0
        assert "semgrep" in scanners
    
    def test_get_enabled_scanners_custom(self, scanner_service):
        """Test getting enabled scanners with custom config."""
        config = {
            "scanners": ["bandit", "safety"],
            "skip_scanners": ["safety"]
        }
        
        scanners = scanner_service._get_enabled_scanners(config)
        
        assert "bandit" in scanners
        assert "safety" not in scanners
    
    @pytest.mark.asyncio
    async def test_scan_progress_updates(self, scanner_service):
        """Test scan progress updates during scanning."""
        scan_id = "test-scan-id"
        
        # Track progress updates
        progress_updates = []
        
        async def mock_update_scan(scan_id, data):
            if "progress" in data:
                progress_updates.append(data["progress"])
        
        with patch('app.services.scanner_service.db.update_scan', side_effect=mock_update_scan):
            scanner_service.file_processor.process_file.return_value = "/tmp/extracted"
            scanner_service.result_processor.process_results.return_value = []
            
            await scanner_service.scan_file(
                scan_id=scan_id,
                file_data=b"test",
                filename="test.py",
                scan_config={}
            )
        
        # Verify progress was updated
        assert len(progress_updates) > 0
        assert max(progress_updates) >= 90