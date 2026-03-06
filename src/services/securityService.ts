import { 
  ThreatsSummary, 
  IoTDeviceStatus, 
  Threat, 
  IoTDevice, 
  SecurityAlert 
} from '../types/security'

// Simulate API delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

// Fake data generators
const generateFakeThreats = (): Threat[] => {
  return [
    {
      id: '1',
      type: 'Malware Detection',
      description: 'Suspicious activity detected on IoT camera cluster',
      severity: 'high',
      timestamp: '2026-03-06T10:30:00Z',
      source: 'Network Scanner'
    },
    {
      id: '2',
      type: 'Unauthorized Access',
      description: 'Multiple failed login attempts on smart thermostat',
      severity: 'medium',
      timestamp: '2026-03-06T09:15:00Z',
      source: 'Authentication Monitor'
    },
    {
      id: '3',
      type: 'Data Breach Attempt',
      description: 'Unusual data transmission from smart doorbell',
      severity: 'high',
      timestamp: '2026-03-06T08:45:00Z',
      source: 'Traffic Analyzer'
    },
    {
      id: '4',
      type: 'Firmware Vulnerability',
      description: 'Outdated firmware detected on smart lights',
      severity: 'low',
      timestamp: '2026-03-06T07:20:00Z',
      source: 'Vulnerability Scanner'
    }
  ]
}

const generateFakeDevices = (): IoTDevice[] => {
  return [
    {
      id: 'dev-001',
      name: 'Smart Camera #1',
      type: 'Security Camera',
      status: 'vulnerable',
      lastSeen: '2 minutes ago',
      ipAddress: '192.168.1.101',
      manufacturer: 'TechCorp'
    },
    {
      id: 'dev-002',
      name: 'Smart Thermostat',
      type: 'Climate Control',
      status: 'warning',
      lastSeen: '5 minutes ago',
      ipAddress: '192.168.1.102',
      manufacturer: 'ClimaTech'
    },
    {
      id: 'dev-003',
      name: 'Smart Doorbell',
      type: 'Access Control',
      status: 'secure',
      lastSeen: '1 minute ago',
      ipAddress: '192.168.1.103',
      manufacturer: 'SecureHome'
    },
    {
      id: 'dev-004',
      name: 'Smart Light Hub',
      type: 'Lighting System',
      status: 'secure',
      lastSeen: '3 minutes ago',
      ipAddress: '192.168.1.104',
      manufacturer: 'LightTech'
    },
    {
      id: 'dev-005',
      name: 'Smart Speaker',
      type: 'Voice Assistant',
      status: 'warning',
      lastSeen: '7 minutes ago',
      ipAddress: '192.168.1.105',
      manufacturer: 'VoiceTech'
    },
    {
      id: 'dev-006',
      name: 'Smart Refrigerator',
      type: 'Kitchen Appliance',
      status: 'secure',
      lastSeen: '4 minutes ago',
      ipAddress: '192.168.1.106',
      manufacturer: 'KitchenSmart'
    }
  ]
}

// Service functions
export async function getThreatsSummary(): Promise<ThreatsSummary> {
  await delay(100) // Simulate API call
  
  const threats = generateFakeThreats()
  
  return {
    activeThreats: threats.filter(t => t.severity === 'high').length + 
                   Math.floor(Math.random() * 5) + 3,
    vulnerabilityScore: Math.floor(Math.random() * 30) + 65, // Score between 65-95
    recentThreats: threats.slice(0, 4)
  }
}

export async function getIoTDeviceStatus(): Promise<IoTDeviceStatus> {
  await delay(150) // Simulate API call
  
  const devices = generateFakeDevices()
  
  return {
    totalDevices: devices.length,
    secureDevices: devices.filter(d => d.status === 'secure').length,
    vulnerableDevices: devices.filter(d => d.status === 'vulnerable').length,
    devices
  }
}

export async function getAllThreats(): Promise<Threat[]> {
  await delay(200) // Simulate API call
  
  // Generate more detailed threats for the threats page
  const baseThreats = generateFakeThreats()
  const additionalThreats: Threat[] = [
    {
      id: '5',
      type: 'Network Intrusion',
      description: 'Suspicious network traffic detected from external IP',
      severity: 'high',
      timestamp: '2026-03-06T06:30:00Z',
      source: 'Network Monitor'
    },
    {
      id: '6',
      type: 'Device Tampering',
      description: 'Physical tampering detected on smart lock',
      severity: 'medium',
      timestamp: '2026-03-06T05:15:00Z',
      source: 'Physical Security'
    },
    {
      id: '7',
      type: 'DDoS Attack',
      description: 'Distributed denial of service targeting smart hub',
      severity: 'high',
      timestamp: '2026-03-06T04:45:00Z',
      source: 'Traffic Monitor'
    }
  ]
  
  return [...baseThreats, ...additionalThreats]
}

export async function getSecurityAlerts(): Promise<SecurityAlert[]> {
  await delay(120) // Simulate API call
  
  return [
    {
      id: 'alert-001',
      title: 'Critical Vulnerability in Smart Camera Firmware',
      description: 'A critical security vulnerability has been discovered in the firmware of TechCorp smart cameras. This vulnerability could allow remote attackers to gain unauthorized access to camera feeds.',
      severity: 'critical',
      category: 'device',
      affectedDevices: ['dev-001'],
      timestamp: '2026-03-06T10:30:00Z',
      resolved: false
    },
    {
      id: 'alert-002',
      title: 'Suspicious Authentication Patterns',
      description: 'Multiple devices are showing unusual authentication patterns that may indicate a coordinated attack.',
      severity: 'high',
      category: 'authentication',
      affectedDevices: ['dev-002', 'dev-005'],
      timestamp: '2026-03-06T09:15:00Z',
      resolved: false
    },
    {
      id: 'alert-003',
      title: 'Malware Signature Detected',
      description: 'Known malware signatures have been detected in network traffic from several IoT devices.',
      severity: 'high',
      category: 'malware',
      affectedDevices: ['dev-001', 'dev-003'],
      timestamp: '2026-03-06T08:45:00Z',
      resolved: true
    }
  ]
}

// Function to simulate refreshing data from external APIs
export async function refreshSecurityData(): Promise<{ success: boolean; message: string }> {
  await delay(2000) // Simulate longer API call to external services
  
  // In a real implementation, this would:
  // 1. Call external threat intelligence APIs
  // 2. Scan network for new devices
  // 3. Update vulnerability databases
  // 4. Refresh malware signatures
  // 5. Update device firmware status
  
  return {
    success: true,
    message: 'Security data refreshed successfully. Found 3 new threats and 2 device updates.'
  }
}
