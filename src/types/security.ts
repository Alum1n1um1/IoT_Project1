export interface Threat {
  id: string
  type: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: string
  source: string
}

export interface ThreatsSummary {
  activeThreats: number
  vulnerabilityScore: number
  recentThreats: Threat[]
}

export interface IoTDevice {
  id: string
  name: string
  type: string
  status: 'secure' | 'warning' | 'vulnerable'
  lastSeen: string
  ipAddress: string
  manufacturer: string
  vulnerabilities?: {
    cves: any[] // From nvd.ts CVE[]
    cwes: any[] // From nvd.ts CWE[]
    kves: any[] // From nvd.ts KVE[]
    cvssScore: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lastUpdated: string
  }
}

export interface IoTDeviceStatus {
  totalDevices: number
  secureDevices: number
  vulnerableDevices: number
  devices: IoTDevice[]
}

export interface SecurityAlert {
  id: string
  title: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  category: 'malware' | 'network' | 'device' | 'authentication' | 'data-breach'
  affectedDevices: string[]
  timestamp: string
  resolved: boolean
}
