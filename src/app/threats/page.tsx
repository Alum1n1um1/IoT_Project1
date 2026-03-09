import { getAllThreats, getSecurityAlerts } from '../../services/securityService'
import ThreatsClientView from '../../components/ThreatsClientView'

export default async function ThreatsPage() {
  // Fetch data server-side for SSR
  const [threats, alerts] = await Promise.all([
    getAllThreats(),
    getSecurityAlerts()
  ])

  return <ThreatsClientView threats={threats} alerts={alerts} />
}
