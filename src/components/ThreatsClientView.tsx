'use client'

import { useMemo, useState } from 'react'
import { SecurityAlert, Threat } from '@/types/security'

interface ThreatsClientViewProps {
  threats: Threat[]
  alerts: SecurityAlert[]
}

export default function ThreatsClientView({ threats, alerts }: ThreatsClientViewProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [alertCategoryFilter, setAlertCategoryFilter] = useState('all')
  const [resolvedFilter, setResolvedFilter] = useState('all')
  const [threatTypeFilter, setThreatTypeFilter] = useState('all')
  const [sourceFilter, setSourceFilter] = useState('all')

  const alertCategories = useMemo(
    () => Array.from(new Set(alerts.map((alert) => alert.category))),
    [alerts]
  )

  const threatTypes = useMemo(
    () => Array.from(new Set(threats.map((threat) => threat.type))),
    [threats]
  )

  const threatSources = useMemo(
    () => Array.from(new Set(threats.map((threat) => threat.source))),
    [threats]
  )

  const normalizedSearch = searchTerm.trim().toLowerCase()

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesSearch =
        normalizedSearch.length === 0 ||
        alert.title.toLowerCase().includes(normalizedSearch) ||
        alert.description.toLowerCase().includes(normalizedSearch) ||
        alert.category.toLowerCase().includes(normalizedSearch)

      const matchesSeverity = severityFilter === 'all' || alert.severity === severityFilter
      const matchesCategory =
        alertCategoryFilter === 'all' || alert.category === alertCategoryFilter
      const matchesResolved =
        resolvedFilter === 'all' ||
        (resolvedFilter === 'resolved' && alert.resolved) ||
        (resolvedFilter === 'open' && !alert.resolved)

      return matchesSearch && matchesSeverity && matchesCategory && matchesResolved
    })
  }, [alerts, normalizedSearch, severityFilter, alertCategoryFilter, resolvedFilter])

  const filteredThreats = useMemo(() => {
    return threats.filter((threat) => {
      const matchesSearch =
        normalizedSearch.length === 0 ||
        threat.type.toLowerCase().includes(normalizedSearch) ||
        threat.description.toLowerCase().includes(normalizedSearch) ||
        threat.source.toLowerCase().includes(normalizedSearch)

      const matchesSeverity = severityFilter === 'all' || threat.severity === severityFilter
      const matchesType = threatTypeFilter === 'all' || threat.type === threatTypeFilter
      const matchesSource = sourceFilter === 'all' || threat.source === sourceFilter

      return matchesSearch && matchesSeverity && matchesType && matchesSource
    })
  }, [threats, normalizedSearch, severityFilter, threatTypeFilter, sourceFilter])

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold text-white mb-8">Threat Analysis</h1>

      <div className="threat-card mb-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-1">Recherche globale</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white placeholder-gray-400"
              placeholder="Titre, description, type, source..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Sévérité</label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="text-sm text-gray-400 flex items-end">
            {filteredAlerts.length} alerte{filteredAlerts.length !== 1 ? 's' : ''} et {filteredThreats.length} menace{filteredThreats.length !== 1 ? 's' : ''}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Catégorie alerte</label>
            <select
              value={alertCategoryFilter}
              onChange={(e) => setAlertCategoryFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes</option>
              {alertCategories.map((category) => (
                <option key={category} value={category}>{category}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Statut alerte</label>
            <select
              value={resolvedFilter}
              onChange={(e) => setResolvedFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes</option>
              <option value="open">Ouvertes</option>
              <option value="resolved">Résolues</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Type menace</label>
            <select
              value={threatTypeFilter}
              onChange={(e) => setThreatTypeFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Tous</option>
              {threatTypes.map((type) => (
                <option key={type} value={type}>{type}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Source menace</label>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes</option>
              {threatSources.map((source) => (
                <option key={source} value={source}>{source}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      <div className="mb-8">
        <h2 className="text-2xl font-semibold text-cyber-blue mb-4">Security Alerts</h2>
        <div className="space-y-4">
          {filteredAlerts.length === 0 ? (
            <div className="threat-card text-gray-400">Aucune alerte ne correspond aux filtres.</div>
          ) : (
            filteredAlerts.map((alert) => (
              <div key={alert.id} className="threat-card">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="text-lg font-semibold text-white">{alert.title}</h3>
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        alert.severity === 'critical' ? 'bg-red-600 text-white' :
                        alert.severity === 'high' ? 'bg-cyber-red text-white' :
                        alert.severity === 'medium' ? 'bg-yellow-500 text-dark-bg' :
                        'bg-cyber-green text-dark-bg'
                      }`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      {alert.resolved && (
                        <span className="px-2 py-1 rounded text-xs font-semibold bg-gray-600 text-white">
                          RESOLVED
                        </span>
                      )}
                    </div>
                    <p className="text-gray-300 mb-3">{alert.description}</p>
                    <div className="flex items-center gap-4 text-sm text-gray-400">
                      <span>Category: {alert.category}</span>
                      <span>Affected devices: {alert.affectedDevices.length}</span>
                      <span>{new Date(alert.timestamp).toLocaleString()}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      <div>
        <h2 className="text-2xl font-semibold text-cyber-blue mb-4">Threat Detection History</h2>
        <div className="threat-card">
          {filteredThreats.length === 0 ? (
            <div className="text-gray-400">Aucune menace ne correspond aux filtres.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="border-b border-gray-600">
                    <th className="py-3 px-4 text-cyber-blue font-semibold">Type</th>
                    <th className="py-3 px-4 text-cyber-blue font-semibold">Description</th>
                    <th className="py-3 px-4 text-cyber-blue font-semibold">Severity</th>
                    <th className="py-3 px-4 text-cyber-blue font-semibold">Source</th>
                    <th className="py-3 px-4 text-cyber-blue font-semibold">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredThreats.map((threat) => (
                    <tr key={threat.id} className="border-b border-gray-700">
                      <td className="py-3 px-4 font-medium text-white">{threat.type}</td>
                      <td className="py-3 px-4 text-gray-300">{threat.description}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-xs font-semibold ${
                          threat.severity === 'critical' ? 'bg-red-600 text-white' :
                          threat.severity === 'high' ? 'bg-cyber-red text-white' :
                          threat.severity === 'medium' ? 'bg-yellow-500 text-dark-bg' :
                          'bg-cyber-green text-dark-bg'
                        }`}>
                          {threat.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-gray-400">{threat.source}</td>
                      <td className="py-3 px-4 text-gray-400">
                        {new Date(threat.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
