'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { CVE, CWE, KVE, IoTDeviceWithVulnerabilities } from '@/types/nvd'

interface VulnerabilityResponse {
  success: boolean
  device: {
    id: string
    name: string
    vendor: string
    product: string
    criticality: string
    manufacturer: string
  }
  vulnerabilities: {
    cves: CVE[]
    cwes: CWE[]
    kves: KVE[]
    cvssScore: number
    criticalCount: number
    highCount: number
    mediumCount: number
    lastUpdated: string
    recommendations?: Array<{
      title: string
      description: string
      priority: 'critical' | 'high' | 'medium' | 'low'
      cwe?: string
    }>
  }
}


export default function CameraDetails() {
  const params = useParams()
  const cameraId = params.cameraId as string

  const [data, setData] = useState<VulnerabilityResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [recommendationPriorityFilter, setRecommendationPriorityFilter] = useState('all')
  const [cveSearchTerm, setCveSearchTerm] = useState('')
  const [cveSeverityFilter, setCveSeverityFilter] = useState('all')
  const [cveKevFilter, setCveKevFilter] = useState('all')

  const calculatePrioritizedRiskScore = (cves: CVE[]): number => {
    if (cves.length === 0) return 0

    let totalScore = 0
    let count = 0

    cves.forEach(cve => {
      const cvss = cve.metrics?.cvssV3?.baseScore || cve.metrics?.cvssV2?.baseScore || 0
      // Note: EPSS data would need to be fetched from database, for now using a placeholder
      const epss = 0.1 // Placeholder, should be fetched from DB
      const kev = cve.inKev ? 1 : 0

      // Formula: (0.6 * CVSS/10 + 0.3 * EPSS + 0.1 * KEV) * 100
      const riskScore = (0.6 * (cvss / 10) + 0.3 * epss + 0.1 * kev) * 100
      totalScore += riskScore
      count++
    })

    return count > 0 ? Math.round(totalScore / count) : 0
  }

  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true)
        const response = await fetch(`/api/vulnerabilities/${cameraId}`)

        if (!response.ok) {
          throw new Error(`Failed to fetch: ${response.statusText}`)
        }

        const result = await response.json()
        setData(result)
        setError(null)
      } catch (err) {
        setError((err as Error).message || 'Failed to load vulnerability data')
        setData(null)
      } finally {
        setLoading(false)
      }
    }

    if (cameraId) {
      fetchData()
    }
  }, [cameraId])

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center justify-center min-h-screen">
          <div className="text-white text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto mb-4"></div>
            <p>Chargement des données de vulnérabilité...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Link href="/" className="text-cyber-blue hover:text-cyber-blue/80 mb-4 inline-block">
          ← Retour au tableau de bord
        </Link>
        <div className="threat-card">
          <h1 className="text-2xl font-bold text-cyber-red mb-4">Erreur</h1>
          <p className="text-gray-400">{error || 'Aucune donnée disponible'}</p>
        </div>
      </div>
    )
  }

  const { device, vulnerabilities } = data

  const recommendationList = vulnerabilities.recommendations || []
  const filteredRecommendations = recommendationList.filter((rec) => {
    return recommendationPriorityFilter === 'all' || rec.priority === recommendationPriorityFilter
  })

  const normalizedCveSearch = cveSearchTerm.trim().toLowerCase()
  const getCveSeverity = (cve: CVE): 'critical' | 'high' | 'medium' | 'low' => {
    const score = cve.metrics?.cvssV3?.baseScore || cve.metrics?.cvssV2?.baseScore || 0
    if (score >= 9) return 'critical'
    if (score >= 7) return 'high'
    if (score >= 4) return 'medium'
    return 'low'
  }

  const filteredCVEs = vulnerabilities.cves.filter((cve) => {
    const matchesSearch =
      normalizedCveSearch.length === 0 ||
      cve.id.toLowerCase().includes(normalizedCveSearch) ||
      (cve.descriptions[0]?.value || '').toLowerCase().includes(normalizedCveSearch)

    const matchesSeverity =
      cveSeverityFilter === 'all' || getCveSeverity(cve) === cveSeverityFilter

    const matchesKev =
      cveKevFilter === 'all' ||
      (cveKevFilter === 'kev-only' && Boolean(cve.inKev)) ||
      (cveKevFilter === 'non-kev' && !cve.inKev)

    return matchesSearch && matchesSeverity && matchesKev
  })

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Back link */}
      <Link href="/" className="text-cyber-blue hover:text-cyber-blue/80 mb-4 inline-block">
        ← Retour au tableau de bord
      </Link>

      {/* Device Header */}
      <div className="threat-card mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">{device.name}</h1>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Marque</p>
            <p className="text-lg font-semibold text-cyber-blue">{device.vendor}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Modèle</p>
            <p className="text-lg font-semibold text-cyber-blue">{device.product}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Criticité</p>
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold ${
              device.criticality === 'critical'
                ? 'bg-red-500/20 text-red-400 border border-red-500/50'
                : device.criticality === 'high'
                  ? 'bg-orange-500/20 text-orange-400 border border-orange-500/50'
                  : device.criticality === 'medium'
                    ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/50'
                    : 'bg-green-500/20 text-green-400 border border-green-500/50'
            }`}>
              {device.criticality === 'low' ? 'Faible' :
               device.criticality === 'medium' ? 'Moyenne' :
               device.criticality === 'high' ? 'Élevée' : 'Critique'}
            </span>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Fabricant</p>
            <p className="text-lg font-semibold text-cyber-blue">{device.manufacturer}</p>
          </div>
        </div>
      </div>

      {/* Vulnerability Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="threat-card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Score CVSS Moyen</h3>
          <p className="text-3xl font-bold text-yellow-400">{vulnerabilities.cvssScore.toFixed(1)}</p>
          <p className="text-xs text-gray-500 mt-2">/10</p>
        </div>

        <div className="threat-card relative">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Score de Risque Priorisé</h3>
          <p className="text-3xl font-bold text-red-400">{calculatePrioritizedRiskScore(vulnerabilities.cves)}</p>
          <p className="text-xs text-gray-500 mt-2">/100</p>
          <div className="absolute top-2 right-2">
            <div className="group relative">
              <button className="text-gray-400 hover:text-white text-sm">ℹ️</button>
              <div className="absolute bottom-full right-0 mb-2 hidden group-hover:block w-64 p-3 bg-gray-800 text-white text-xs rounded shadow-lg border border-gray-600 z-10">
                <p className="font-semibold mb-1">Formule de calcul :</p>
                <p>(0.6 × CVSS/10 + 0.3 × EPSS + 0.1 × KEV) × 100</p>
                <p className="mt-2">CVSS: Sévérité technique (0-10)</p>
                <p>EPSS: Probabilité d'exploitation (0-1)</p>
                <p>KEV: Exploitation connue (0-1)</p>
              </div>
            </div>
          </div>
        </div>

        <div className="threat-card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Critiques</h3>
          <p className="text-3xl font-bold text-cyber-red">{vulnerabilities.criticalCount}</p>
          <p className="text-xs text-gray-500 mt-2">CVE CVSS ≥ 9.0</p>
        </div>

        <div className="threat-card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Élevées</h3>
          <p className="text-3xl font-bold text-orange-500">{vulnerabilities.highCount}</p>
          <p className="text-xs text-gray-500 mt-2">CVE CVSS 7.0-8.9</p>
        </div>
      </div>

      {/* Last Updated */}
      <div className="text-sm text-gray-500 mb-8">
        Dernière mise à jour: {new Date(vulnerabilities.lastUpdated).toLocaleString('fr-FR')}
      </div>

      {/* Recommendations Section */}
      {recommendationList.length > 0 && (
        <div className="threat-card mb-8">
          <h3 className="text-lg font-semibold text-cyber-blue mb-4 flex items-center">
            <span className="mr-2">🛡️</span>
            Recommandations de Sécurité
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Priorité recommandation</label>
              <select
                value={recommendationPriorityFilter}
                onChange={(e) => setRecommendationPriorityFilter(e.target.value)}
                className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
              >
                <option value="all">Toutes</option>
                <option value="critical">Critique</option>
                <option value="high">Élevée</option>
                <option value="medium">Moyenne</option>
                <option value="low">Faible</option>
              </select>
            </div>
            <div className="text-sm text-gray-400 flex items-end">
              {filteredRecommendations.length} recommandation{filteredRecommendations.length !== 1 ? 's' : ''}
            </div>
          </div>
          <div className="space-y-3">
            {filteredRecommendations.length === 0 ? (
              <div className="text-sm text-gray-400">Aucune recommandation ne correspond au filtre sélectionné.</div>
            ) : (
              filteredRecommendations.map((rec, index) => (
              <div key={index} className="flex items-start space-x-3 p-3 bg-gray-800 rounded-lg border border-gray-600">
                <div className="flex-shrink-0">
                  <span className={`inline-flex items-center justify-center w-6 h-6 rounded-full text-xs font-bold ${
                    rec.priority === 'critical' ? 'bg-red-600 text-white' :
                    rec.priority === 'high' ? 'bg-orange-600 text-white' :
                    rec.priority === 'medium' ? 'bg-yellow-600 text-white' :
                    'bg-blue-600 text-white'
                  }`}>
                    {rec.priority === 'critical' ? 'C' : rec.priority === 'high' ? 'H' : rec.priority === 'medium' ? 'M' : 'L'}
                  </span>
                </div>
                <div className="flex-1">
                  <p className="text-sm text-gray-200 font-medium">{rec.title}</p>
                  <p className="text-xs text-gray-400 mt-1">{rec.description}</p>
                  {rec.cwe && (
                    <p className="text-xs text-cyber-blue mt-1">CWE: {rec.cwe}</p>
                  )}
                </div>
              </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* CVEs Section */}
      <div className="threat-card mb-8">
        <h2 className="text-2xl font-bold text-cyber-blue mb-4">
          Vulnérabilités CVE ({filteredCVEs.length}/{vulnerabilities.cves.length})
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Recherche CVE</label>
            <input
              type="text"
              value={cveSearchTerm}
              onChange={(e) => setCveSearchTerm(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white placeholder-gray-400"
              placeholder="ID CVE ou description..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Sévérité CVE</label>
            <select
              value={cveSeverityFilter}
              onChange={(e) => setCveSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes</option>
              <option value="critical">Critique</option>
              <option value="high">Élevée</option>
              <option value="medium">Moyenne</option>
              <option value="low">Faible</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Statut KEV</label>
            <select
              value={cveKevFilter}
              onChange={(e) => setCveKevFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Tous</option>
              <option value="kev-only">KEV uniquement</option>
              <option value="non-kev">Sans KEV</option>
            </select>
          </div>
        </div>

        {filteredCVEs.length === 0 ? (
          <p className="text-gray-400">Aucune vulnérabilité ne correspond aux filtres.</p>
        ) : (
          <div className="space-y-4">
            {filteredCVEs.map(cve => (
              <div key={cve.id} className="p-4 bg-gray-800 rounded border-l-4 border-gray-600">
                <div className="flex items-start justify-between mb-2">
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyber-blue hover:underline font-semibold"
                  >
                    {cve.id}
                  </a>
                  <div className="flex gap-2">
                    {cve.metrics.cvssV3 && (
                      <>
                        <span
                          className={`px-2 py-1 rounded text-xs font-semibold ${
                            (cve.metrics.cvssV3.baseScore || 0) >= 9
                              ? 'bg-cyber-red text-white'
                              : (cve.metrics.cvssV3.baseScore || 0) >= 7
                                ? 'bg-orange-500 text-white'
                                : (cve.metrics.cvssV3.baseScore || 0) >= 4
                                  ? 'bg-yellow-500 text-dark-bg'
                                  : 'bg-cyber-green text-dark-bg'
                          }`}
                        >
                          CVSS {(cve.metrics.cvssV3.baseScore || 0).toFixed(1)}
                        </span>
                        <span className="px-2 py-1 rounded text-xs font-semibold bg-gray-700 text-gray-200">
                          {cve.metrics.cvssV3.baseSeverity}
                        </span>
                      </>
                    )}
                  </div>
                </div>

                <p className="text-sm text-gray-300 mb-2">
                  {cve.descriptions[0]?.value || 'No description available'}
                </p>

                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Publié: {new Date(cve.published).toLocaleDateString('fr-FR')}</span>
                  <span>Modifié: {new Date(cve.lastModified).toLocaleDateString('fr-FR')}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CWEs Section */}
      <div className="threat-card mb-8">
        <h2 className="text-2xl font-bold text-cyber-blue mb-4">
          Faiblesses CWE ({vulnerabilities.cwes.length})
        </h2>

        {vulnerabilities.cwes.length === 0 ? (
          <p className="text-gray-400">Aucune CWE trouvée.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {vulnerabilities.cwes.map(cwe => (
              <div key={cwe.id} className="p-4 bg-gray-800 rounded">
                <a
                  href={`https://cwe.mitre.org/data/definitions/${cwe.id.split('-')[1]}.html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyber-blue hover:underline font-semibold"
                >
                  {cwe.id}
                </a>
                <p className="text-sm text-gray-300 mt-2">{cwe.name}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* KVEs Section */}
      <div className="threat-card">
        <h2 className="text-2xl font-bold text-cyber-blue mb-4">
          Exploits Connus KVE ({vulnerabilities.kves.length})
        </h2>

        {vulnerabilities.kves.length === 0 ? (
          <p className="text-gray-400">Aucun exploit public trouvé.</p>
        ) : (
          <div className="space-y-3">
            {vulnerabilities.kves.map((kve, idx) => (
              <div key={idx} className="p-4 bg-gray-800 rounded border-l-4 border-cyber-red">
                <p className="font-semibold text-white mb-1">{kve.title}</p>
                <p className="text-sm text-gray-400 mb-2">Related to: {kve.cveId}</p>
                <a
                  href={kve.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyber-blue hover:underline text-sm"
                >
                  Voir l'exploit →
                </a>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
