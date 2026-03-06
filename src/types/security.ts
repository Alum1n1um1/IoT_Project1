export interface Threat {
  id: string
  type: string
  description: string
  severity: 'low' | 'medium' | 'high'
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
