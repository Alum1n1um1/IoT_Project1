import pool from '../lib/db'
import {
  ThreatsSummary,
  IoTDeviceStatus,
  Threat,
  IoTDevice,
  SecurityAlert
} from '../types/security'
import { vulnerabilityService } from './vulnerabilityService'
import { getUserCameras } from './cameraService'

// Simulate API delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))


// Service functions
export async function getThreatsSummary(userId: number): Promise<ThreatsSummary> {
  await delay(100) // Simulate API call

  try {
    // Get user's cameras and enrich with vulnerability data
    const cameras = await getUserCameras(userId)
    const enrichedDevices = await Promise.all(
      cameras.map(camera => vulnerabilityService.enrichDeviceWithVulns(camera))
    )

    // Get all CVEs from enriched devices
    const allCVEs = enrichedDevices.flatMap(d => d.vulnerabilities?.cves || [])

    // Get all CVSS scores (for average calculation)
    const allCVSSScores = enrichedDevices
      .map(d => d.vulnerabilities?.cvssScore || 0)
      .filter(score => score > 0)

    // Build threats summary with real data
    const activeThreats = enrichedDevices.reduce(
      (sum, d) => sum + (d.vulnerabilities?.criticalCount || 0),
      0
    )

    const vulnerabilityScore =
      allCVSSScores.length > 0
        ? Math.round(allCVSSScores.reduce((a, b) => a + b, 0) / allCVSSScores.length)
        : 0

    // Convert CVEs to Threat format, sorted by date
    const recentThreats: Threat[] = allCVEs
      .sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime())
      .slice(0, 4)
      .map(cve => ({
        id: cve.id,
        type: 'CVE',
        description: `${cve.id}: ${cve.descriptions[0]?.value.substring(0, 80) || 'No description'}`,
        severity: vulnerabilityService.cvssToSeverity(cve.metrics.cvssV3?.baseScore),
        timestamp: cve.published,
        source: 'NVD'
      }))

    return {
      activeThreats,
      vulnerabilityScore,
      recentThreats
    }
  } catch (error) {
    console.error('Error in getThreatsSummary:', error)
    // Return safe defaults on error
    return {
      activeThreats: 0,
      vulnerabilityScore: 0,
      recentThreats: []
    }
  }
}

// Get user's cameras and convert them to IoT devices for dashboard
export async function getIoTDeviceStatus(userId: number): Promise<IoTDeviceStatus> {
  await delay(150) // Simulate API call

  try {
    // Get user's cameras
    const cameras = await getUserCameras(userId)

    // Enrich each camera with vulnerability data
    const devices: IoTDevice[] = await Promise.all(
      cameras.map(camera => vulnerabilityService.enrichDeviceWithVulns(camera))
    )

    return {
      totalDevices: devices.length,
      secureDevices: devices.filter(d => d.status === 'secure').length,
      vulnerableDevices: devices.filter(d => d.status === 'vulnerable').length,
      devices
    }
  } catch (error) {
    console.error('Database error:', error)
    // Fallback to empty data
    return {
      totalDevices: 0,
      secureDevices: 0,
      vulnerableDevices: 0,
      devices: []
    }
  }
}

// Helper functions (deprecated - kept for backward compatibility)
// Threat summary status is now based on real CVSS data
function getRandomStatus(criticity: string): 'secure' | 'warning' | 'vulnerable' {
  const random = Math.random()

  switch (criticity) {
    case 'critical':
      return random < 0.7 ? 'vulnerable' : random < 0.9 ? 'warning' : 'secure'
    case 'high':
      return random < 0.4 ? 'vulnerable' : random < 0.7 ? 'warning' : 'secure'
    case 'medium':
      return random < 0.2 ? 'vulnerable' : random < 0.5 ? 'warning' : 'secure'
    case 'low':
      return random < 0.1 ? 'vulnerable' : random < 0.3 ? 'warning' : 'secure'
    default:
      return 'secure'
  }
}

function getRandomLastSeen(): string {
  const minutes = Math.floor(Math.random() * 10) + 1
  return `${minutes} minute${minutes > 1 ? 's' : ''}`
}

export async function getAllThreats(): Promise<Threat[]> {
  await delay(200) // Simulate API call

  // Return empty array - threats are now fetched dynamically from real CVE data
  // This is kept for backward compatibility with threats page
  // Real threat data is fetched from getThreatsSummary() which uses NVD data
  return []
}

export async function getSecurityAlerts(): Promise<SecurityAlert[]> {
  await delay(120) // Simulate API call
  
  return [
    {
      id: 'alert-001',
      title: 'Vulnérabilité Critique dans Firmware Caméras',
      description: 'Une vulnérabilité critique a été découverte dans le firmware des caméras. Cette vulnérabilité pourrait permettre aux attaquants d\'accéder aux flux vidéo.',
      severity: 'critical',
      category: 'device',
      affectedDevices: ['dev-001'],
      timestamp: '2026-03-06T10:30:00Z',
      resolved: false
    },
    {
      id: 'alert-002',
      title: 'Modèles d\'Authentification Suspects',
      description: 'Plusieurs appareils montrent des modèles d\'authentification inhabituels qui pourraient indiquer une attaque coordonnée.',
      severity: 'high',
      category: 'authentication',
      affectedDevices: ['dev-002', 'dev-005'],
      timestamp: '2026-03-06T09:15:00Z',
      resolved: false
    },
    {
      id: 'alert-003',
      title: 'Signature Malware Détectée',
      description: 'Des signatures de malware connues ont été détectées dans le trafic réseau de plusieurs appareils IoT.',
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
    message: 'Données de sécurité actualisées avec succès. 3 nouvelles menaces et 2 mises à jour d\'appareils trouvées.'
  }
}
