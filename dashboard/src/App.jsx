import React from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAuth } from './hooks/useAuth'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import BotConfig from './pages/BotConfig'
import Giveaways from './pages/Giveaways'
import Leveling from './pages/Leveling'
import Polls from './pages/Polls'
import Tickets from './pages/Tickets'
import Moderation from './pages/Moderation'
import LoginPage from './pages/LoginPage'
import LandingPage from './pages/LandingPage'
import DocsPage from './pages/DocsPage'
import FAQPage from './pages/FAQPage'
import queryClient from './lib/queryClient'

function DashboardApp() {
  const { isAuthenticated, isLoading, user } = useAuth()

  if (isLoading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner"></div>
        <p>Loading...</p>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <LoginPage />
  }

  return (
    <div className="dashboard-container">
      <Sidebar user={user} />
      <main className="main-content">
        <Routes>
          <Route path="" element={<Dashboard />} />
          <Route path="config" element={<BotConfig />} />
          <Route path="giveaways" element={<Giveaways />} />
          <Route path="leveling" element={<Leveling />} />
          <Route path="polls" element={<Polls />} />
          <Route path="tickets" element={<Tickets />} />
          <Route path="moderation" element={<Moderation />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Router>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/docs" element={<DocsPage />} />
          <Route path="/faq" element={<FAQPage />} />
          <Route path="/dashboard/*" element={<DashboardApp />} />
        </Routes>
      </Router>
    </QueryClientProvider>
  )
}

export default App