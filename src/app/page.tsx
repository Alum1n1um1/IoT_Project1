import { getThreatsSummary, getIoTDeviceStatus } from '../services/securityService'
import { cookies } from 'next/headers'
import { verifyToken } from '../services/authService'
import { redirect } from 'next/navigation'

export default async function Dashboard() {
  // Get authenticated user
  const cookieStore = await cookies()
  const token = cookieStore.get('auth-token')?.value
  
  if (!token) {
    redirect('/login')
  }
  
  const user = await verifyToken(token)
  if (!user) {
    redirect('/login')
  }

  // Fetch data server-side for SSR
  const threatsSummary = await getThreatsSummary()
  const deviceStatus = await getIoTDeviceStatus(user.id)

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <h1 className="text-3xl font-bold text-white mb-8">Tableau de Bord Sécurité IoT</h1>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Menaces Actives</h3>
          <p className="text-3xl font-bold text-cyber-red">{threatsSummary.activeThreats}</p>
          <p className="text-sm text-gray-400">Problèmes de sécurité critiques détectés</p>
        </div>
        
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Appareils Surveillés</h3>
          <p className="text-3xl font-bold text-cyber-green">{deviceStatus.totalDevices}</p>
          <p className="text-sm text-gray-400">Appareils IoT sous surveillance</p>
        </div>
        
        <div className="threat-card">
          <h3 className="text-lg font-semibold text-cyber-blue mb-2">Score Vulnérabilité</h3>
          <p className="text-3xl font-bold text-yellow-400">{threatsSummary.vulnerabilityScore}/100</p>
          <p className="text-sm text-gray-400">Évaluation globale de sécurité</p>
        </div>
      </div>

      {/* Recent Threats */}
      <div className="threat-card mb-8">
        <h3 className="text-xl font-semibold text-cyber-blue mb-4">Activité Récente des Menaces</h3>
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
        <h3 className="text-xl font-semibold text-cyber-blue mb-4">État des Appareils IoT</h3>
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
              <p className="text-xs text-gray-500">Vu: {device.lastSeen}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
