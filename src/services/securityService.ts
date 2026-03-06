import pool from '../lib/db'
import { 
  ThreatsSummary, 
  IoTDeviceStatus, 
  Threat, 
  IoTDevice, 
  SecurityAlert 
} from '../types/security'

// Simulate API delay
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

// Generate fake threats (will be replaced with real threat intelligence APIs)
const generateFakeThreats = (): Threat[] => {
  return [
    {
      id: '1',
      type: 'Détection Malware',
      description: 'Activité suspecte détectée sur cluster de caméras IoT',
      severity: 'high',
      timestamp: '2026-03-06T10:30:00Z',
      source: 'Scanner Réseau'
    },
    {
      id: '2',
      type: 'Accès Non Autorisé',
      description: 'Tentatives de connexion échouées multiples sur thermostat',
      severity: 'medium',
      timestamp: '2026-03-06T09:15:00Z',
      source: 'Moniteur Authentification'
    },
    {
      id: '3',
      type: 'Tentative Violation Données',
      description: 'Transmission de données inhabituelle depuis sonnette connectée',
      severity: 'high',
      timestamp: '2026-03-06T08:45:00Z',
      source: 'Analyseur Trafic'
    },
    {
      id: '4',
      type: 'Vulnérabilité Firmware',
      description: 'Firmware obsolète détecté sur éclairages connectés',
      severity: 'low',
      timestamp: '2026-03-06T07:20:00Z',
      source: 'Scanner Vulnérabilités'
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

// Get user's cameras and convert them to IoT devices for dashboard
export async function getIoTDeviceStatus(userId: number): Promise<IoTDeviceStatus> {
  await delay(150) // Simulate API call
  
  try {
    const client = await pool.connect()
    
    const result = await client.query(
      'SELECT * FROM cameras WHERE user_id = $1',
      [userId]
    )
    
    client.release()
    
    const cameras = result.rows
    
    // Convert cameras to IoT devices with simulated status
    const devices: IoTDevice[] = cameras.map((camera, index) => ({
      id: camera.id.toString(),
      name: camera.name,
      type: 'Caméra de Sécurité',
      status: getRandomStatus(camera.criticity),
      lastSeen: getRandomLastSeen(),
      ipAddress: `192.168.1.${100 + index}`,
      manufacturer: camera.brand
    }))
    
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

// Helper functions
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
  
  // Generate more detailed threats for the threats page
  const baseThreats = generateFakeThreats()
  const additionalThreats: Threat[] = [
    {
      id: '5',
      type: 'Intrusion Réseau',
      description: 'Trafic réseau suspect détecté depuis IP externe',
      severity: 'high',
      timestamp: '2026-03-06T06:30:00Z',
      source: 'Moniteur Réseau'
    },
    {
      id: '6',
      type: 'Manipulation Appareil',
      description: 'Manipulation physique détectée sur serrure connectée',
      severity: 'medium',
      timestamp: '2026-03-06T05:15:00Z',
      source: 'Sécurité Physique'
    },
    {
      id: '7',
      type: 'Attaque DDoS',
      description: 'Déni de service distribué ciblant hub connecté',
      severity: 'high',
      timestamp: '2026-03-06T04:45:00Z',
      source: 'Moniteur Trafic'
    }
  ]
  
  return [...baseThreats, ...additionalThreats]
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
