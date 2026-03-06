import { getThreatsSummary, getIoTDeviceStatus } from '../services/securityService'

export default async function Dashboard() {
  // Fetch data server-side for SSR
  const threatsSummary = await getThreatsSummary()
  const deviceStatus = await getIoTDeviceStatus()

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold text-white mb-8">IoT Security Dashboard</h1>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Active Threats</h3>
          <p className="text-3xl font-bold text-cyber-red">{threatsSummary.activeThreats}</p>
          <p className="text-sm text-gray-400">Critical security issues detected</p>
        </div>
        
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Monitored Devices</h3>
          <p className="text-3xl font-bold text-cyber-green">{deviceStatus.totalDevices}</p>
          <p className="text-sm text-gray-400">IoT devices under surveillance</p>
        </div>
        
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Vulnerability Score</h3>
          <p className="text-3xl font-bold text-yellow-400">{threatsSummary.vulnerabilityScore}/100</p>
          <p className="text-sm text-gray-400">Overall security rating</p>
        </div>
      </div>

      {/* Recent Threats */}
      <div className="threat-card mb-8">
        <h3 className="text-xl font-semibold text-cyber-blue mb-4">Recent Threat Activity</h3>
        <div className="space-y-3">
          {threatsSummary.recentThreats.map((threat, index) => (
            <div key={index} className="flex items-center justify-between p-3 bg-gray-800 rounded">
              <div>
                <p className="font-semibold text-white">{threat.type}</p>
                <p className="text-sm text-gray-400">{threat.description}</p>
              </div>
              <span className={`px-2 py-1 rounded text-xs font-semibold ${
                threat.severity === 'high' ? 'bg-cyber-red text-white' :
                threat.severity === 'medium' ? 'bg-yellow-500 text-dark-bg' :
                'bg-cyber-green text-dark-bg'
              }`}>
                {threat.severity.toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Device Status */}
      <div className="threat-card">
        <h3 className="text-xl font-semibold text-cyber-blue mb-4">IoT Device Status</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {deviceStatus.devices.map((device, index) => (
            <div key={index} className="p-3 bg-gray-800 rounded">
              <div className="flex items-center justify-between mb-2">
                <h4 className="font-semibold text-white">{device.name}</h4>
                <span className={`w-3 h-3 rounded-full ${
                  device.status === 'secure' ? 'bg-cyber-green' :
                  device.status === 'warning' ? 'bg-yellow-500' :
                  'bg-cyber-red'
                }`}></span>
              </div>
              <p className="text-sm text-gray-400">{device.type}</p>
              <p className="text-xs text-gray-500">Last seen: {device.lastSeen}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
