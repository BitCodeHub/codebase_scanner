import { create } from 'zustand'

interface ScanResult {
  id: number
  severity: string
  category: string
  file_path: string
  line_number: number
  vulnerability_type: string
  description: string
  fix_priority: number
  false_positive: boolean
}

interface Scan {
  id: number
  project_id: number
  status: string
  scan_type: string
  started_at: string
  completed_at?: string
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
}

interface ScanStore {
  scans: Scan[]
  currentScan: Scan | null
  scanResults: ScanResult[]
  setScans: (scans: Scan[]) => void
  setCurrentScan: (scan: Scan | null) => void
  setScanResults: (results: ScanResult[]) => void
  updateScan: (id: number, updates: Partial<Scan>) => void
}

export const useScanStore = create<ScanStore>((set) => ({
  scans: [],
  currentScan: null,
  scanResults: [],
  setScans: (scans) => set({ scans }),
  setCurrentScan: (scan) => set({ currentScan: scan }),
  setScanResults: (results) => set({ scanResults: results }),
  updateScan: (id, updates) => set((state) => ({
    scans: state.scans.map(scan => 
      scan.id === id ? { ...scan, ...updates } : scan
    )
  }))
}))