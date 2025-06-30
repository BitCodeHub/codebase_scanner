from supabase import create_client, Client
from typing import Optional, Dict, Any, List
import asyncio
import logging
from app.config import settings

logger = logging.getLogger(__name__)

class SupabaseClient:
    """Supabase database client for the scanner application"""
    
    def __init__(self):
        self._client: Optional[Client] = None
        self._initialized = False
    
    @property
    def client(self) -> Client:
        """Lazy initialization of Supabase client"""
        if not self._initialized:
            if not settings.supabase_url or not settings.supabase_service_key:
                raise ValueError("Supabase credentials not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_KEY environment variables.")
            
            self._client = create_client(
                settings.supabase_url,
                settings.supabase_service_key
            )
            self._initialized = True
        return self._client
    
    # Projects
    async def get_projects(self, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get projects for a user"""
        try:
            response = self.client.table("projects")\
                .select("*")\
                .eq("owner_id", user_id)\
                .eq("is_active", True)\
                .order("created_at", desc=True)\
                .range(offset, offset + limit - 1)\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching projects: {e}")
            raise
    
    async def get_project(self, project_id: int, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific project"""
        try:
            response = self.client.table("projects")\
                .select("*")\
                .eq("id", project_id)\
                .eq("owner_id", user_id)\
                .single()\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching project {project_id}: {e}")
            return None
    
    async def create_project(self, project_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new project"""
        try:
            response = self.client.table("projects")\
                .insert(project_data)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error creating project: {e}")
            raise
    
    async def update_project(self, project_id: int, user_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a project"""
        try:
            response = self.client.table("projects")\
                .update(updates)\
                .eq("id", project_id)\
                .eq("owner_id", user_id)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error updating project {project_id}: {e}")
            raise
    
    async def delete_project(self, project_id: int, user_id: str) -> bool:
        """Soft delete a project"""
        try:
            self.client.table("projects")\
                .update({"is_active": False})\
                .eq("id", project_id)\
                .eq("owner_id", user_id)\
                .execute()
            return True
        except Exception as e:
            logger.error(f"Error deleting project {project_id}: {e}")
            return False
    
    # Scans
    async def get_scans(self, project_id: Optional[int] = None, user_id: Optional[str] = None, 
                       limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get scans with optional filtering"""
        try:
            query = self.client.table("scans").select("*")
            
            if project_id:
                query = query.eq("project_id", project_id)
            if user_id:
                query = query.eq("user_id", user_id)
            
            response = query.order("created_at", desc=True)\
                .range(offset, offset + limit - 1)\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching scans: {e}")
            raise
    
    async def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific scan"""
        try:
            response = self.client.table("scans")\
                .select("*")\
                .eq("id", scan_id)\
                .single()\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching scan {scan_id}: {e}")
            return None
    
    async def create_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new scan"""
        try:
            response = self.client.table("scans")\
                .insert(scan_data)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            raise
    
    async def update_scan(self, scan_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a scan"""
        try:
            response = self.client.table("scans")\
                .update(updates)\
                .eq("id", scan_id)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error updating scan {scan_id}: {e}")
            raise
    
    # Scan Results
    async def get_scan_results(self, scan_id: int, severity: Optional[str] = None, 
                              category: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get scan results with optional filtering"""
        try:
            query = self.client.table("scan_results")\
                .select("*")\
                .eq("scan_id", scan_id)
            
            if severity:
                query = query.eq("severity", severity)
            if category:
                query = query.eq("category", category)
            
            response = query.order("fix_priority", desc=False)\
                .limit(limit)\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching scan results for scan {scan_id}: {e}")
            raise
    
    async def create_scan_result(self, result_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a scan result"""
        try:
            response = self.client.table("scan_results")\
                .insert(result_data)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error creating scan result: {e}")
            raise
    
    async def create_scan_results_batch(self, results_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create multiple scan results in batch"""
        try:
            response = self.client.table("scan_results")\
                .insert(results_data)\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error creating scan results batch: {e}")
            raise
    
    async def update_scan_result(self, result_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update a scan result"""
        try:
            response = self.client.table("scan_results")\
                .update(updates)\
                .eq("id", result_id)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error updating scan result {result_id}: {e}")
            raise
    
    # Reports
    async def get_reports(self, project_id: Optional[int] = None, user_id: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        """Get reports with optional filtering"""
        try:
            query = self.client.table("reports").select("*")
            
            if project_id:
                query = query.eq("project_id", project_id)
            if user_id:
                query = query.eq("user_id", user_id)
            
            response = query.order("created_at", desc=True)\
                .limit(limit)\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching reports: {e}")
            raise
    
    async def create_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new report"""
        try:
            response = self.client.table("reports")\
                .insert(report_data)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error creating report: {e}")
            raise
    
    # User Profiles
    async def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user profile"""
        try:
            response = self.client.table("user_profiles")\
                .select("*")\
                .eq("id", user_id)\
                .single()\
                .execute()
            return response.data
        except Exception as e:
            logger.error(f"Error fetching user profile {user_id}: {e}")
            return None
    
    async def upsert_user_profile(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update user profile"""
        try:
            response = self.client.table("user_profiles")\
                .upsert(profile_data)\
                .execute()
            return response.data[0]
        except Exception as e:
            logger.error(f"Error upserting user profile: {e}")
            raise
    
    # Storage
    async def upload_file(self, bucket: str, file_path: str, file_data: bytes) -> str:
        """Upload file to Supabase storage"""
        try:
            response = self.client.storage.from_(bucket).upload(file_path, file_data)
            return file_path
        except Exception as e:
            logger.error(f"Error uploading file to {bucket}/{file_path}: {e}")
            raise
    
    async def download_file(self, bucket: str, file_path: str) -> bytes:
        """Download file from Supabase storage"""
        try:
            response = self.client.storage.from_(bucket).download(file_path)
            return response
        except Exception as e:
            logger.error(f"Error downloading file from {bucket}/{file_path}: {e}")
            raise
    
    async def delete_file(self, bucket: str, file_path: str) -> bool:
        """Delete file from Supabase storage"""
        try:
            self.client.storage.from_(bucket).remove([file_path])
            return True
        except Exception as e:
            logger.error(f"Error deleting file from {bucket}/{file_path}: {e}")
            return False
    
    async def get_file_url(self, bucket: str, file_path: str, expires_in: int = 3600) -> str:
        """Get signed URL for file"""
        try:
            response = self.client.storage.from_(bucket).create_signed_url(file_path, expires_in)
            return response.get('signedURL', '')
        except Exception as e:
            logger.error(f"Error getting signed URL for {bucket}/{file_path}: {e}")
            raise

# Global database instance
db = SupabaseClient()

# Authentication helpers
async def verify_user_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token and return user data"""
    try:
        response = db.client.auth.get_user(token)
        return response.user.dict() if response.user else None
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return None

async def get_user_from_token(token: str) -> Optional[str]:
    """Extract user ID from JWT token"""
    user_data = await verify_user_token(token)
    return user_data.get('id') if user_data else None