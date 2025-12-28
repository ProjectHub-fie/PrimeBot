import React, { useState, useEffect } from 'react'
import { Activity, Users, MessageSquare, Zap, Gift, Vote, TrendingUp, Settings } from 'lucide-react'

const Dashboard = () => {
  const [botStats, setBotStats] = useState({
    servers: 'Loading...',
    uptime: 'Loading...',
    commands: 0,
    status: 'offline'
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchBotStats()
    const interval = setInterval(fetchBotStats, 30000) // Update every 30 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchBotStats = async () => {
    try {
      const response = await fetch('/api/botinfo')
      if (response.ok) {
        const data = await response.json()
        setBotStats({
          servers: data.servers || 0,
          uptime: data.uptime || 'Offline',
          commands: data.commands ? data.commands.length : 0,
          status: 'online'
        })
      } else {
        setBotStats(prev => ({ ...prev, status: 'offline' }))
      }
    } catch (error) {
      console.error('Error fetching bot stats:', error)
      setBotStats(prev => ({ ...prev, status: 'offline' }))
    } finally {
      setLoading(false)
    }
  }

  const statCards = [
    {
      icon: Users,
      label: 'Servers',
      value: botStats.servers,
      color: 'var(--primary-color)'
    },
    {
      icon: Activity,
      label: 'Uptime',
      value: botStats.uptime,
      color: 'var(--success-color)'
    },
    {
      icon: MessageSquare,
      label: 'Commands',
      value: botStats.commands,
      color: 'var(--warning-color)'
    },
    {
      icon: Zap,
      label: 'Status',
      value: botStats.status === 'online' ? 'Online' : 'Offline',
      color: botStats.status === 'online' ? 'var(--success-color)' : 'var(--danger-color)'
    }
  ]

  return (
    <div>
      <h1 style={{ marginBottom: '30px', color: 'var(--dark-color)' }}>
        Dashboard Overview
      </h1>

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>Quick Actions</h3>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <a href="/giveaways" className="btn btn-primary">
            <Gift size={16} />
            Create Giveaway
          </a>
          <a href="/polls" className="btn btn-success">
            <Vote size={16} />
            Create Poll
          </a>
          <a href="/leveling" className="btn btn-warning">
            <TrendingUp size={16} />
            Manage Levels
          </a>
          <a href="/config" className="btn btn-primary">
            <Settings size={16} />
            Bot Settings
          </a>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>System Information</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
          <div>
            <h4>Bot Version</h4>
            <p>v2.5.0</p>
          </div>
          <div>
            <h4>Last Updated</h4>
            <p>August 2025</p>
          </div>
          <div>
            <h4>Features</h4>
            <p>Giveaways, Leveling, Polls, Tickets, Moderation</p>
          </div>
          <div>
            <h4>Database</h4>
            <p>MySQL with Drizzle ORM</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard