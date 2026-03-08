// NVD API Service - Fetch CVE data from NIST
import { CVE, CWE, VulnerabilityCacheEntry } from '../types/nvd'

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const EPSS_URL = 'https://api.first.org/data/v1/epss'

// Helper to add delay between requests (rate limiting)
const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

// NVD v2.0 API Response structure
interface NVDAPIResponse {
  vulnerabilities?: Array<{
    cve: {
      id: string
      descriptions?: Array<{
        lang: string
        value: string
      }>
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: {
            baseScore: number
            baseSeverity: string
            version: string
          }
        }>
        cvssMetricV30?: Array<{
          cvssData: {
            baseScore: number
            baseSeverity: string
            version: string
          }
        }>
        cvssMetricV2?: Array<{
          cvssData: {
            baseScore: number
            baseSeverity?: string
            severity?: string
          }
        }>
      }
      weaknesses?: Array<{
        description?: Array<{
          lang: string
          value: string
        }>
      }>
      published?: string
      lastModified?: string
    }
  }>
  totalResults?: number
}

interface EPSSResponse {
  data?: Array<{
    cve: string
    epss: number | null
    percentile: number | null
    date: string
  }>
}

class NVDService {
  private lastRequestTime = 0
  private REQUEST_DELAY = 200 // 5 req/sec max (200ms between requests)

  /**
   * Main method: Search CVE by camera vendor and product
   */
  async searchCVEs(vendor: string, product: string): Promise<CVE[]> {
    // Try searches in order of specificity
    const searchStrategies = [
      `"${vendor}" "${product}"`, // Exact match
      `${vendor} ${product}`, // Phrase match
      vendor // Fallback to vendor only
    ]

    for (const query of searchStrategies) {
      console.log(`[NVD] Searching: ${query}`)
      const cves = await this.nvdQuery(query)

      if (cves.length > 0) {
        console.log(`[NVD] Found ${cves.length} CVEs for: ${query}`)
        return cves
      }
    }

    console.log(`[NVD] No CVEs found for "${vendor}" "${product}"`)
    return []
  }

  /**
   * Query NVD API with retry logic
   */
  private async nvdQuery(keywordSearch: string): Promise<CVE[]> {
    // Rate limiting
    const now = Date.now()
    const elapsed = now - this.lastRequestTime
    if (elapsed < this.REQUEST_DELAY) {
      await delay(this.REQUEST_DELAY - elapsed)
    }

    // Exponential backoff retry (3 attempts)
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        this.lastRequestTime = Date.now()

        const url = new URL(NVD_API_URL)
        url.searchParams.append('keywordSearch', keywordSearch)
        url.searchParams.append('resultsPerPage', '100')

        const controller = new AbortController()
        const timeout = setTimeout(() => controller.abort(), 5000) // 5 second timeout

        const response = await fetch(url.toString(), {
          signal: controller.signal,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Referer': 'https://nvd.nist.gov/'
          }
        })

        clearTimeout(timeout)

        if (!response.ok) {
          throw new Error(`NVD API error: ${response.status} ${response.statusText}`)
        }

        const data: NVDAPIResponse = await response.json()

        // Parse CVE data from NVD response format
        const cves = this.parseCVEs(data)
        return cves
      } catch (error) {
        console.error(`[NVD] Attempt ${attempt + 1}/3 failed:`, error)

        if (attempt === 2) {
          // Last attempt failed
          console.error(`[NVD] All attempts failed for "${keywordSearch}"`)
          return []
        }

        // Exponential backoff: 1s, 2s, 4s
        const backoffMs = Math.pow(2, attempt) * 1000
        console.log(`[NVD] Retrying in ${backoffMs}ms...`)
        await delay(backoffMs)
      }
    }

    return []
  }

  /**
   * Parse CVE data from NVD v2.0 API response
   */
  private parseCVEs(data: NVDAPIResponse): CVE[] {
    if (!data.vulnerabilities) {
      return []
    }

    return data.vulnerabilities
      .map(item => {
        const cve = item.cve
        const cveId = cve.id
        const descriptions = cve.descriptions || []
        const description = descriptions.find(d => d.lang === 'en')?.value || descriptions[0]?.value || ''

        // Extract CVSS scores (prioritize v3.1 → v3.0 → v2.0)
        let baseScore: number | undefined
        let baseSeverity: string | undefined
        let version: string | undefined

        if (cve.metrics?.cvssMetricV31?.[0]) {
          const cvssV3 = cve.metrics.cvssMetricV31[0].cvssData
          baseScore = cvssV3.baseScore
          baseSeverity = cvssV3.baseSeverity
          version = cvssV3.version
        } else if (cve.metrics?.cvssMetricV30?.[0]) {
          const cvssV3 = cve.metrics.cvssMetricV30[0].cvssData
          baseScore = cvssV3.baseScore
          baseSeverity = cvssV3.baseSeverity
          version = cvssV3.version
        } else if (cve.metrics?.cvssMetricV2?.[0]) {
          const cvssV2 = cve.metrics.cvssMetricV2[0].cvssData
          baseScore = cvssV2.baseScore
          baseSeverity = cvssV2.baseSeverity || cvssV2.severity
          version = '2.0'
        }

        return {
          id: cveId,
          sourceIdentifier: 'NVD',
          published: cve.published || '',
          lastModified: cve.lastModified || '',
          vulnStatus: 'Analyzed',
          descriptions: [
            {
              lang: 'en',
              value: description
            }
          ],
          metrics: {
            cvssV3:
              baseScore !== undefined && version?.startsWith('3')
                ? {
                    baseScore,
                    baseSeverity: baseSeverity || 'UNKNOWN',
                    version: version || '3.1'
                  }
                : undefined,
            cvssV2:
              baseScore !== undefined && version === '2.0'
                ? {
                    baseScore,
                    baseSeverity: baseSeverity || 'UNKNOWN'
                  }
                : undefined
          },
          references: []
        } as CVE
      })
      .filter(cve => cve.id) // Remove invalid entries
  }

  /**
   * Extract CWEs from CVE weaknesses (NVD v2.0 format)
   */
  extractCWEs(cves: CVE[]): CWE[] {
    const cwes = new Map<string, CWE>()

    cves.forEach(cve => {
      // From description: look for CWE-XXX patterns
      const description = cve.descriptions[0]?.value || ''
      const cweMatches = description.match(/CWE-\d+/g) || []

      cweMatches.forEach(match => {
        const id = match
        if (!cwes.has(id)) {
          cwes.set(id, {
            id,
            name: this.getCWEName(id),
            description: ''
          })
        }
      })
    })

    return Array.from(cwes.values())
  }

  /**
   * Get CWE name from ID (common ones)
   */
  private getCWEName(cweId: string): string {
    const cweNames: { [key: string]: string } = {
      'CWE-20': 'Improper Input Validation',
      'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command',
      'CWE-79': 'Improper Neutralization of Input During Web Page Generation',
      'CWE-89': 'SQL Injection',
      'CWE-119': 'Improper Restriction of Operations within the Bounds',
      'CWE-125': 'Out-of-bounds Read',
      'CWE-200': 'Exposure of Sensitive Information',
      'CWE-287': 'Improper Authentication',
      'CWE-400': 'Uncontrolled Resource Consumption',
      'CWE-401': 'Missing Release of Memory after Effective Lifetime',
      'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
      'CWE-476': 'NULL Pointer Dereference',
      'CWE-611': 'Improper Restriction of XML External Entity Reference'
    }

    return cweNames[cweId] || cweId
  }

  /**
   * Search for public exploits (simulated - no external API call)
   * In production, could integrate with exploit-db or similar
   */
  async searchPublicExploits(cves: CVE[]) {
    // Filter only critical and high severity CVEs
    const vulnerableCVEs = cves.filter(cve => {
      const score = cve.metrics.cvssV3?.baseScore || 0
      return score >= 7.0
    })

    // Return mock exploit info (in production, call exploit-db API)
    return vulnerableCVEs.map(cve => ({
      cveId: cve.id,
      source: 'NVD',
      url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
      title: `Public vulnerability ${cve.id}`
    }))
  }

  /**
   * Calculate average CVSS score
   */
  calculateAverageCVSS(cves: CVE[]): number {
    if (cves.length === 0) return 0

    const scores = cves
      .map(cve => cve.metrics.cvssV3?.baseScore || 0)
      .filter(score => score > 0)

    if (scores.length === 0) return 0

    return scores.reduce((a, b) => a + b, 0) / scores.length
  }

  /**
   * Fetch EPSS scores for CVEs from FIRST API
   */
  async getEPSSScores(cveIds: string[]): Promise<Map<string, { epss: number; percentile: number }>> {
    if (cveIds.length === 0) return new Map()

    const epssMap = new Map<string, { epss: number; percentile: number }>()

    try {
      // Batch request (max 100 CVE IDs per request)
      const batches = []
      for (let i = 0; i < cveIds.length; i += 100) {
        batches.push(cveIds.slice(i, i + 100))
      }

      for (const batch of batches) {
        const params = new URLSearchParams()
        params.append('cve', batch.join(','))

        const response = await fetch(`${EPSS_URL}?${params.toString()}`, {
          signal: AbortSignal.timeout(5000),
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive'
          }
        })

        if (!response.ok) continue

        const data: EPSSResponse = await response.json()
        if (data.data) {
          data.data.forEach(entry => {
            if (entry.cve && entry.epss !== null && entry.percentile !== null) {
              epssMap.set(entry.cve, {
                epss: entry.epss,
                percentile: entry.percentile
              })
            }
          })
        }

        // Rate limiting
        await delay(500)
      }
    } catch (error) {
      console.error('[NVD] Error fetching EPSS:', error)
    }

    return epssMap
  }

  /**
   * Check if CVE is in CISA KEV (Known Exploited Vulnerabilities)
   */
  async checkKEVStatus(cveIds: string[]): Promise<Map<string, boolean>> {
    const kevMap = new Map<string, boolean>()

    try {
      const response = await fetch(KEV_URL, {
        signal: AbortSignal.timeout(10000),
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'Accept': 'application/json',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Connection': 'keep-alive'
        }
      })

      if (!response.ok) return kevMap

      const data = await response.json()
      const vulnerabilities = data.vulnerabilities || []

      const cveIdSet = new Set(cveIds.map(id => id.toUpperCase()))
      vulnerabilities.forEach((vuln: any) => {
        const cveId = vuln.cveID?.toUpperCase()
        if (cveId && cveIdSet.has(cveId)) {
          kevMap.set(cveId, true)
        }
      })
    } catch (error) {
      console.error('[NVD] Error fetching KEV:', error)
    }

    return kevMap
  }

  /**
   * Calculate risk score combining CVSS, EPSS, and KEV
   * Following the pattern from risk.py:
   * Risk = (0.6 * CVSS_norm) + (0.3 * EPSS) + (0.1 * KEV_flag)
   * If ransomware KEV: Risk *= 1.1
   */
  calculateRiskScore(
    cvssScore: number | undefined,
    epssScore: number | undefined,
    inKEV: boolean
  ): number {
    const cvssNorm = (cvssScore || 0) / 10.0
    const epss = epssScore || 0

    // Weighted calculation
    let riskScore = 0.6 * cvssNorm + 0.3 * epss + 0.1 * (inKEV ? 1.0 : 0.0)

    // Return as 0-100 scale
    return Math.min(100, Math.max(0, riskScore * 100))
  }
}

// Singleton instance
export const nvdService = new NVDService()
