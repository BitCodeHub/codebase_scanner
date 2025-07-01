# Claude Code Assistant Notes

## System Overview
- **Frontend**: React with TypeScript, deployed on Render at https://codebase-scanner-frontend.onrender.com
- **Backend**: FastAPI with Python, deployed on Render at https://codebase-scanner-backend.onrender.com
- **Database**: Supabase PostgreSQL
- **Authentication**: Supabase Auth with JWT tokens

## Important Database Schema Notes
- The `projects` table uses BIGSERIAL for IDs (auto-incrementing bigint), NOT UUIDs
- The `owner_id` field is a UUID that references auth.users
- When querying scans by project_id, convert the string ID to integer: `parseInt(project.id)`

## Common Issues and Solutions

### 1. API URL Configuration
- Production frontend must point to the backend URL, not localhost
- Use `getApiUrl()` from `frontend/src/utils/api-config.ts` for dynamic URL detection

### 2. Dependency Conflicts
- Use flexible version ranges in requirements.txt (e.g., `>=2.7.0,<2.8.0`)
- Let pip resolve complex dependencies instead of pinning exact versions

### 3. Supabase Client Initialization
- May encounter "proxy" parameter errors with certain supabase versions
- Currently using supabase>=2.7.0,<2.8.0 to avoid this issue

### 4. Project Creation Flow
1. Frontend calls projectService.createProject()
2. Backend creates project with auto-generated BIGSERIAL ID
3. Frontend waits 500ms then refreshes project list
4. Projects are displayed with scan counts fetched separately

## Debugging Tips
- Check browser console for API response logs
- Use the "Debug" button on Projects page to test direct API calls
- Use the "Refresh" button to manually reload projects
- Check Render logs for backend errors

## Key Files
- Backend project API: `/backend/src/api/projects.py`
- Frontend project service: `/frontend/src/services/projectService.ts`
- Database schema: `/supabase_schema.sql`
- API configuration: `/frontend/src/utils/api-config.ts`