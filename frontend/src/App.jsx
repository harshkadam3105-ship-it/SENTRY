import { HashRouter, Routes, Route } from 'react-router-dom'
import SOCOverview from './pages/SOCOverview'
import IncidentDetail from './pages/IncidentDetail'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<SOCOverview />} />
        <Route path="/incident/:id" element={<IncidentDetail />} />
        {/* Catch-all → back to overview */}
        <Route path="*" element={<SOCOverview />} />
      </Routes>
    </HashRouter>
  )
}
