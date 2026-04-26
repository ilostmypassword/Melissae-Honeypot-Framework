import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js'
import { Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Search from './pages/Search'
import ThreatIntel from './pages/ThreatIntel'
import Map from './pages/Map'
import Agents from './pages/Agents'
import ActivityStats from './pages/ActivityStats'
import AttackerStats from './pages/AttackerStats'

ChartJS.register(
  CategoryScale, LinearScale, PointElement,
  LineElement, BarElement, ArcElement, Tooltip, Legend, Filler
)

// Root application component with routing
export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/search" element={<Search />} />
        <Route path="/threats" element={<ThreatIntel />} />
        <Route path="/map" element={<Map />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/stats/activity" element={<ActivityStats />} />
        <Route path="/stats/attackers" element={<AttackerStats />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

