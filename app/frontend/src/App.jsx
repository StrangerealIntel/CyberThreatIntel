import React from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Dashboard from './pages/Dashboard'
import Analyses from './pages/Analyses'
import IOCs from './pages/IOCs'
import APTGroups from './pages/APTGroups'
import Search from './pages/Search'

const queryClient = new QueryClient()

function Navigation() {
  const location = useLocation()

  return (
    <div className="navbar">
      <h1>🛡️ CyberThreatIntel</h1>
      <nav>
        <Link to="/" className={location.pathname === '/' ? 'active' : ''}>
          Dashboard
        </Link>
        <Link to="/analyses" className={location.pathname === '/analyses' ? 'active' : ''}>
          Analyses
        </Link>
        <Link to="/iocs" className={location.pathname === '/iocs' ? 'active' : ''}>
          IOCs
        </Link>
        <Link to="/apt-groups" className={location.pathname === '/apt-groups' ? 'active' : ''}>
          APT Groups
        </Link>
        <Link to="/search" className={location.pathname === '/search' ? 'active' : ''}>
          Search
        </Link>
      </nav>
    </div>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <div className="app">
          <Navigation />
          <div className="container">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/analyses" element={<Analyses />} />
              <Route path="/iocs" element={<IOCs />} />
              <Route path="/apt-groups" element={<APTGroups />} />
              <Route path="/search" element={<Search />} />
            </Routes>
          </div>
        </div>
      </Router>
    </QueryClientProvider>
  )
}

export default App
