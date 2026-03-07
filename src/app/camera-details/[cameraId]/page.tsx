'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { CVE, CWE, KVE } from '@/types/nvd'

interface VulnerabilityData {
  success: boolean
  device: {
    id: string
    name: string
    brand: string
    model: string
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
  }
}

export default function CameraDetails() {
  const params = useParams()
  const cameraId = params.cameraId as string

  const [data, setData] = useState<VulnerabilityData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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
            <p className="text-lg font-semibold text-cyber-blue">{device.brand}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Modèle</p>
            <p className="text-lg font-semibold text-cyber-blue">{device.model}</p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider">Criticité</p>
            <p
              className={`text-lg font-semibold capitalize ${
                device.criticality === 'critical'
                  ? 'text-cyber-red'
                  : device.criticality === 'high'
                    ? 'text-orange-500'
                    : device.criticality === 'medium'
                      ? 'text-yellow-500'
                      : 'text-cyber-green'
              }`}
            >
              {device.criticality}
            </p>
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

        <div className="threat-card">
          <h3 className="text-sm font-semibold text-gray-400 uppercase mb-2">Moyennes</h3>
          <p className="text-3xl font-bold text-yellow-500">{vulnerabilities.mediumCount}</p>
          <p className="text-xs text-gray-500 mt-2">CVE CVSS 4.0-6.9</p>
        </div>
      </div>

      {/* Last Updated */}
      <div className="text-sm text-gray-500 mb-8">
        Dernière mise à jour: {new Date(vulnerabilities.lastUpdated).toLocaleString('fr-FR')}
      </div>

      {/* CVEs Section */}
      <div className="threat-card mb-8">
        <h2 className="text-2xl font-bold text-cyber-blue mb-4">
          Vulnérabilités CVE ({vulnerabilities.cves.length})
        </h2>

        {vulnerabilities.cves.length === 0 ? (
          <p className="text-gray-400">Aucune vulnérabilité trouvée pour ce modèle.</p>
        ) : (
          <div className="space-y-4">
            {vulnerabilities.cves.map(cve => (
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
