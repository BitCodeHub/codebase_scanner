#!/usr/bin/env python3
"""Upload test project with vulnerable dependencies"""
import requests
import json

API_BASE = "http://localhost:8000/api"

def upload_test_project():
    print("📁 Uploading test project with vulnerable dependencies...")
    
    # 1. Login
    login_data = {
        "username": "demo",
        "password": "demo123"
    }
    
    response = requests.post(f"{API_BASE}/auth/token", data=login_data)
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 2. Create new project
    project_data = {
        "name": "Dependency Test Project",
        "description": "Test project with vulnerable dependencies (lodash, express, jquery)"
    }
    
    response = requests.post(f"{API_BASE}/projects", json=project_data, headers=headers)
    if response.status_code != 200:
        print(f"❌ Failed to create project: {response.text}")
        return None
    
    project = response.json()
    project_id = project["id"]
    print(f"✅ Created project: {project['name']} (ID: {project_id})")
    
    # 3. Upload zip file
    with open("test_project_with_deps.zip", "rb") as f:
        files = {"file": ("test_project_with_deps.zip", f, "application/zip")}
        response = requests.post(
            f"{API_BASE}/projects/{project_id}/upload", 
            files=files, 
            headers={"Authorization": f"Bearer {token}"}
        )
    
    if response.status_code != 200:
        print(f"❌ Failed to upload file: {response.text}")
        return None
    
    print("✅ Uploaded test project with vulnerable dependencies")
    return project_id

if __name__ == "__main__":
    project_id = upload_test_project()
    if project_id:
        print(f"\n🎯 Ready to test! Use project ID: {project_id}")
        print("Now run a scan on this project to test dependency scanning.")
    else:
        print("❌ Upload failed")