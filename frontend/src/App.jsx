import { BrowserRouter, Routes, Route } from 'react-router-dom'
import SOCOverview from './pages/SOCOverview'
import IncidentDetail from './pages/IncidentDetail'
import ErrorBoundary from './components/ErrorBoundary'

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<SOCOverview />} />
          <Route path="/incident/:id" element={<IncidentDetail />} />
          {/* Catch-all → back to overview */}
          <Route path="*" element={<SOCOverview />} />
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
