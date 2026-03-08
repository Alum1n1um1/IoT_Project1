import {
  ThreatsSummary,
  IoTDeviceStatus,
  Threat,
  SecurityAlert
} from '../types/security'

const PYTHON_VULN_API_URL =
  process.env.PYTHON_VULN_API_URL || 'http://localhost:8000'
const DEFAULT_USER_ID = Number(process.env.SECURITY_DEFAULT_USER_ID || '1')

function buildApiUrl(path: string, query?: Record<string, string | number | undefined>) {
  const url = new URL(path, PYTHON_VULN_API_URL)
  if (query) {
    Object.entries(query).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value))
      }
    })
  }
  return url.toString()
}

async function fetchPythonApi<T>(
  path: string,
  options?: RequestInit,
  query?: Record<string, string | number | undefined>
): Promise<T> {
  const response = await fetch(buildApiUrl(path, query), {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {})
    },
    cache: 'no-store'
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Python API error ${response.status}: ${errorText}`)
  }

  return (await response.json()) as T
}

function isSeverity(value: unknown): value is Threat['severity'] {
  return value === 'low' || value === 'medium' || value === 'high' || value === 'critical'
}

function normalizeThreat(raw: any): Threat {
  const severity = isSeverity(raw?.severity) ? raw.severity : 'low'
  return {
    id: String(raw?.id || ''),
    type: String(raw?.type || 'CVE'),
    description: String(raw?.description || 'No description'),
    severity,
    timestamp: String(raw?.timestamp || new Date().toISOString()),
    source: String(raw?.source || 'NVD')
  }
}

function normalizeAlert(raw: any): SecurityAlert {
  const severity = isSeverity(raw?.severity) ? raw.severity : 'low'
  const categoryValues: SecurityAlert['category'][] = [
    'malware',
    'network',
    'device',
    'authentication',
    'data-breach'
  ]
  const category = categoryValues.includes(raw?.category) ? raw.category : 'device'

  return {
    id: String(raw?.id || ''),
    title: String(raw?.title || 'Security alert'),
    description: String(raw?.description || 'No description'),
    severity,
    category,
    affectedDevices: Array.isArray(raw?.affectedDevices)
      ? raw.affectedDevices.map((id: unknown) => String(id))
      : [],
    timestamp: String(raw?.timestamp || new Date().toISOString()),
    resolved: Boolean(raw?.resolved)
  }
}


// Service functions
export async function getThreatsSummary(userId: number): Promise<ThreatsSummary> {
  try {
    const data = await fetchPythonApi<any>(
      '/api/v1/threats/summary',
      undefined,
      { user_id: userId }
    )

    return {
      activeThreats: Number(data?.activeThreats || 0),
      vulnerabilityScore: Number(data?.vulnerabilityScore || 0),
      recentThreats: Array.isArray(data?.recentThreats)
        ? data.recentThreats.map(normalizeThreat)
        : []
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
  try {
    const data = await fetchPythonApi<any>(
      '/api/v1/devices/status',
      undefined,
      { user_id: userId }
    )
    const devices = Array.isArray(data?.devices) ? data.devices : []

    return {
      totalDevices: Number(data?.totalDevices || devices.length),
      secureDevices: Number(
        data?.secureDevices || devices.filter((d: any) => d?.status === 'secure').length
      ),
      vulnerableDevices: Number(
        data?.vulnerableDevices || devices.filter((d: any) => d?.status === 'vulnerable').length
      ),
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

export async function getAllThreats(): Promise<Threat[]> {
  try {
    const data = await fetchPythonApi<any[]>(
      '/api/v1/threats',
      undefined,
      { user_id: DEFAULT_USER_ID }
    )
    return Array.isArray(data) ? data.map(normalizeThreat) : []
  } catch (error) {
    console.error('Error in getAllThreats:', error)
    return []
  }
}

export async function getSecurityAlerts(): Promise<SecurityAlert[]> {
  try {
    const data = await fetchPythonApi<any[]>(
      '/api/v1/alerts',
      undefined,
      { user_id: DEFAULT_USER_ID }
    )
    return Array.isArray(data) ? data.map(normalizeAlert) : []
  } catch (error) {
    console.error('Error in getSecurityAlerts:', error)
    return []
  }
}

export async function refreshSecurityData(): Promise<{ success: boolean; message: string }> {
  try {
    const result = await fetchPythonApi<any>('/api/v1/sync', {
      method: 'POST',
      body: JSON.stringify({
        user_id: DEFAULT_USER_ID,
        max_results: 100
      })
    })

    if (!result?.success) {
      return {
        success: false,
        message: result?.error || 'Python sync failed'
      }
    }

    return {
      success: true,
      message: `Actualisation terminée: ${result.succeeded || 0} caméra(s) synchronisée(s), ${result.failed || 0} échec(s).`
    }
  } catch (error) {
    console.error('Error in refreshSecurityData:', error)
    return {
      success: false,
      message: 'Failed to refresh security data from microservice'
    }
  }
}
