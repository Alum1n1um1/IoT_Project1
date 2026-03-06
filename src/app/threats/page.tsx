import { getAllThreats, getSecurityAlerts } from '../../services/securityService'

export default async function ThreatsPage() {
  // Fetch data server-side for SSR
  const [threats, alerts] = await Promise.all([
    getAllThreats(),
    getSecurityAlerts()
  ])

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold text-white mb-8">Threat Analysis</h1>
      
      {/* Security Alerts */}
      <div className="mb-8">
        <h2 className="text-2xl font-semibold text-cyber-blue mb-4">Security Alerts</h2>
        <div className="space-y-4">
          {alerts.map((alert) => (
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
          ))}
        </div>
      </div>

      {/* Threat Detection History */}
      <div>
        <h2 className="text-2xl font-semibold text-cyber-blue mb-4">Threat Detection History</h2>
        <div className="threat-card">
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
                {threats.map((threat) => (
                  <tr key={threat.id} className="border-b border-gray-700">
                    <td className="py-3 px-4 font-medium text-white">{threat.type}</td>
                    <td className="py-3 px-4 text-gray-300">{threat.description}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
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
        </div>
      </div>
    </div>
  )
}
