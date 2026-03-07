// NVD API Types - CVE, CWE, KVE structures

export interface CVEMetrics {
  cvssV3?: {
    baseScore: number // 0-10
    baseSeverity: string // CRITICAL, HIGH, MEDIUM, LOW, NONE
    version: string
  }
  cvssV2?: {
    baseScore: number
    baseSeverity: string
  }
}

export interface CVE {
  id: string // CVE-2024-XXXXX
  sourceIdentifier: string
  published: string
  lastModified: string
  vulnStatus: string
  descriptions: Array<{
    lang: string
    value: string
  }>
  metrics: CVEMetrics
  references?: Array<{
    url: string
    source: string
  }>
}

export interface CWE {
  name: string // e.g. "Improper Input Validation"
  id: string // CWE-20
  description?: string
}

export interface KVE {
  cveId: string
  source: string // exploit source
  url: string // link to exploit
  title: string
  publicationDate?: string
}

export interface VulnerabilityCacheEntry {
  cves: CVE[]
  cwes: CWE[]
  kves: KVE[]
  cvssScore: number // moyenne des CVSS
  lastUpdated: number // timestamp
  ttl: number // TTL in seconds
}

export interface IoTDeviceWithVulnerabilities {
  id: string
  name: string
  type: string
  status: 'secure' | 'warning' | 'vulnerable'
  lastSeen: string
  ipAddress: string
  manufacturer: string
  vulnerabilities?: {
    cves: CVE[]
    cwes: CWE[]
    kves: KVE[]
    cvssScore: number
    criticalCount: number // CVE with CVSS >= 9.0
    highCount: number // CVE with CVSS 7.0-8.9
    mediumCount: number // CVE with CVSS 4.0-6.9
    lastUpdated: string // ISO string
  }
}
