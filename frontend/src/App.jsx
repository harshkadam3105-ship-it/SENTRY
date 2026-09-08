import { HashRouter, Routes, Route } from 'react-router-dom'
import SOCOverview from './pages/SOCOverview'
import IncidentDetail from './pages/IncidentDetail'
import AiCopilotModal from './components/AiCopilotModal'

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<SOCOverview />} />
        <Route path="/incident/:id" element={<IncidentDetail />} />
        {/* Catch-all → back to overview */}
        <Route path="*" element={<SOCOverview />} />
      </Routes>
      <AiCopilotModal />
    </HashRouter>
  )
}
