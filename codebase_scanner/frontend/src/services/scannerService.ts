import { getApiUrl } from '../utils/api-config';

const API_URL = getApiUrl();

export const scannerService = {
  // Universal file upload scan
  async uploadUniversalScan(formData: FormData) {
    const response = await fetch(`${API_URL}/api/scans/upload-universal`, {
      method: 'POST',
      body: formData,
    });
    
    if (!response.ok) {
      throw new Error('Failed to start scan');
    }
    
    return response.json();
  },

  // Get universal scan status
  async getUniversalScanStatus(scanId: string) {
    const response = await fetch(`${API_URL}/api/scans/upload-universal/${scanId}/status`);
    
    if (!response.ok) {
      throw new Error('Failed to get scan status');
    }
    
    return response.json();
  },

  // Get universal scan results
  async getUniversalScanResults(scanId: string) {
    const response = await fetch(`${API_URL}/api/scans/upload-universal/${scanId}/results`);
    
    if (!response.ok) {
      throw new Error('Failed to get scan results');
    }
    
    return response.json();
  },

  // GitHub repository scan
  async scanGitHubRepository(data: {
    repository_url: string;
    scan_type: string;
    enable_ai_analysis: boolean;
  }) {
    const response = await fetch(`${API_URL}/api/scans/github`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    
    if (!response.ok) {
      throw new Error('Failed to start GitHub scan');
    }
    
    return response.json();
  },

  // Get GitHub scan status
  async getGitHubScanStatus(scanId: string) {
    const response = await fetch(`${API_URL}/api/scans/github/${scanId}/status`);
    
    if (!response.ok) {
      throw new Error('Failed to get scan status');
    }
    
    return response.json();
  },

  // Get GitHub scan results
  async getGitHubScanResults(scanId: string) {
    const response = await fetch(`${API_URL}/api/scans/github/${scanId}/results`);
    
    if (!response.ok) {
      throw new Error('Failed to get scan results');
    }
    
    return response.json();
  },

  // Test scanner tools
  async testScannerTools() {
    const response = await fetch(`${API_URL}/api/test/scanner-tools-cached`);
    
    if (!response.ok) {
      throw new Error('Failed to test scanner tools');
    }
    
    return response.json();
  },
};