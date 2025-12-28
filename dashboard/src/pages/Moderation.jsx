import React, { useState, useEffect } from 'react'
import { Shield, AlertTriangle, Users, Ban } from 'lucide-react'

const Moderation = () => {
  const [moderationData, setModerationData] = useState({
    warnings: [],
    bans: [],
    kicks: []
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchModerationData()
  }, [])

  const fetchModerationData = async () => {
    try {
      const response = await fetch('/api/moderation')
      if (response.ok) {
        const data = await response.json()
        setModerationData(data)
      }
    } catch (error) {
      console.error('Error fetching moderation data:', error)
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString()
  }

  const getModerationStats = () => {
    return {
      totalWarnings: moderationData.warnings.length,
      totalBans: moderationData.bans.length,
      totalKicks: moderationData.kicks.length,
      totalActions: moderationData.warnings.length + moderationData.bans.length + moderationData.kicks.length
    }
  }

  const stats = getModerationStats()

  return (
    <div>
      <h1 style={{ marginBottom: '30px' }}>Moderation Dashboard</h1>

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
        </div>
      ) : (
        <>
          <div className="stats-grid" style={{ marginBottom: '30px' }}>
            <div className="stat-card">
              <Shield size={40} color="var(--primary-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--primary-color)' }}>
                {stats.totalActions}
              </div>
              <div className="stat-label">Total Actions</div>
            </div>
            
            <div className="stat-card">
              <AlertTriangle size={40} color="var(--warning-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--warning-color)' }}>
                {stats.totalWarnings}
              </div>
              <div className="stat-label">Warnings</div>
            </div>
            
            <div className="stat-card">
              <Users size={40} color="var(--danger-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--danger-color)' }}>
                {stats.totalKicks}
              </div>
              <div className="stat-label">Kicks</div>
            </div>
            
            <div className="stat-card">
              <Ban size={40} color="var(--danger-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--danger-color)' }}>
                {stats.totalBans}
              </div>
              <div className="stat-label">Bans</div>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginBottom: '20px' }}>Recent Moderation Actions</h3>
            
            {stats.totalActions === 0 ? (
              <p style={{ textAlign: 'center', color: 'var(--gray-color)', padding: '40px' }}>
                No moderation actions recorded yet. Actions will appear here when moderators use bot commands.
              </p>
            ) : (
              <div className="table-container" style={{ overflowX: 'auto' }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>User</th>
                      <th>Moderator</th>
                      <th>Reason</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {/* Warnings */}
                    {moderationData.warnings.map((warning) => (
                      <tr key={`warning-${warning.id}`}>
                        <td>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '12px',
                            fontSize: '0.8rem',
                            fontWeight: '500',
                            backgroundColor: 'var(--warning-color)',
                            color: 'var(--dark-color)'
                          }}>
                            Warning
                          </span>
                        </td>
                        <td>{warning.username || `User ${warning.userId}`}</td>
                        <td>{warning.moderator || 'Unknown'}</td>
                        <td style={{ maxWidth: '200px' }}>
                          {warning.reason || 'No reason provided'}
                        </td>
                        <td>{formatDate(warning.createdAt)}</td>
                      </tr>
                    ))}
                    
                    {/* Kicks */}
                    {moderationData.kicks.map((kick) => (
                      <tr key={`kick-${kick.id}`}>
                        <td>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '12px',
                            fontSize: '0.8rem',
                            fontWeight: '500',
                            backgroundColor: 'var(--danger-color)',
                            color: 'white'
                          }}>
                            Kick
                          </span>
                        </td>
                        <td>{kick.username || `User ${kick.userId}`}</td>
                        <td>{kick.moderator || 'Unknown'}</td>
                        <td style={{ maxWidth: '200px' }}>
                          {kick.reason || 'No reason provided'}
                        </td>
                        <td>{formatDate(kick.createdAt)}</td>
                      </tr>
                    ))}
                    
                    {/* Bans */}
                    {moderationData.bans.map((ban) => (
                      <tr key={`ban-${ban.id}`}>
                        <td>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '12px',
                            fontSize: '0.8rem',
                            fontWeight: '500',
                            backgroundColor: 'var(--danger-color)',
                            color: 'white'
                          }}>
                            Ban
                          </span>
                        </td>
                        <td>{ban.username || `User ${ban.userId}`}</td>
                        <td>{ban.moderator || 'Unknown'}</td>
                        <td style={{ maxWidth: '200px' }}>
                          {ban.reason || 'No reason provided'}
                        </td>
                        <td>{formatDate(ban.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h3 style={{ marginBottom: '20px' }}>Moderation Tools</h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
              <div>
                <h4>Available Commands</h4>
                <ul style={{ color: 'var(--gray-color)', fontSize: '0.9rem', paddingLeft: '20px' }}>
                  <li>/warn - Warn a user</li>
                  <li>/kick - Kick a user from server</li>
                  <li>/ban - Ban a user from server</li>
                  <li>/unban - Unban a user</li>
                  <li>/mute - Temporarily mute a user</li>
                </ul>
              </div>
              
              <div>
                <h4>Auto-Moderation</h4>
                <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                  The bot can automatically detect and handle spam, inappropriate content, and rule violations.
                </p>
              </div>
              
              <div>
                <h4>Logging</h4>
                <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                  All moderation actions are logged and can be reviewed here for transparency and accountability.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default Moderation