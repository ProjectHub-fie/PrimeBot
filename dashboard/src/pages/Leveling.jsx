import React, { useState, useEffect } from 'react'
import { TrendingUp, Award, Users, Star } from 'lucide-react'

const Leveling = () => {
  const [topUsers, setTopUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedUser, setSelectedUser] = useState('')
  const [badgeToAward, setBadgeToAward] = useState('')
  const [awarding, setAwarding] = useState(false)

  const availableBadges = [
    { id: 'helper', name: 'Helpful Hand', emoji: '🤝' },
    { id: 'contributor', name: 'Contributor', emoji: '🛠️' },
    { id: 'event', name: 'Event Participant', emoji: '🎉' },
    { id: 'creative', name: 'Creative Mind', emoji: '🎨' },
    { id: 'moderator', name: 'Community Guardian', emoji: '🛡️' }
  ]

  useEffect(() => {
    fetchLevelingData()
  }, [])

  const fetchLevelingData = async () => {
    try {
      const response = await fetch('/api/leveling/top')
      if (response.ok) {
        const data = await response.json()
        setTopUsers(data)
      }
    } catch (error) {
      console.error('Error fetching leveling data:', error)
    } finally {
      setLoading(false)
    }
  }

  const awardBadge = async () => {
    if (!selectedUser || !badgeToAward) return
    
    setAwarding(true)
    try {
      const response = await fetch('/api/leveling/badge', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          userId: selectedUser,
          badgeId: badgeToAward
        })
      })
      
      if (response.ok) {
        await fetchLevelingData()
        setSelectedUser('')
        setBadgeToAward('')
      }
    } catch (error) {
      console.error('Error awarding badge:', error)
    } finally {
      setAwarding(false)
    }
  }

  const getRankIcon = (index) => {
    switch (index) {
      case 0: return '🥇'
      case 1: return '🥈'
      case 2: return '🥉'
      default: return `#${index + 1}`
    }
  }

  return (
    <div>
      <h1 style={{ marginBottom: '30px' }}>Leveling System</h1>

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>Award Badge to User</h3>
        
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: '15px', alignItems: 'end' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">User ID</label>
            <input
              type="text"
              value={selectedUser}
              onChange={(e) => setSelectedUser(e.target.value)}
              className="form-input"
              placeholder="Enter Discord User ID"
            />
          </div>
          
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Badge</label>
            <select
              value={badgeToAward}
              onChange={(e) => setBadgeToAward(e.target.value)}
              className="form-select"
            >
              <option value="">Select a badge</option>
              {availableBadges.map((badge) => (
                <option key={badge.id} value={badge.id}>
                  {badge.emoji} {badge.name}
                </option>
              ))}
            </select>
          </div>
          
          <button
            onClick={awardBadge}
            disabled={!selectedUser || !badgeToAward || awarding}
            className="btn btn-primary"
          >
            {awarding ? 'Awarding...' : 'Award Badge'}
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
        </div>
      ) : (
        <div className="card">
          <h3 style={{ marginBottom: '20px' }}>Top Users</h3>
          
          {topUsers.length === 0 ? (
            <p style={{ textAlign: 'center', color: 'var(--gray-color)', padding: '40px' }}>
              No leveling data available yet. Users will appear here as they gain XP.
            </p>
          ) : (
            <div className="table-container" style={{ overflowX: 'auto' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>User</th>
                    <th>Level</th>
                    <th>XP</th>
                    <th>Messages</th>
                    <th>Badges</th>
                  </tr>
                </thead>
                <tbody>
                  {topUsers.map((user, index) => (
                    <tr key={user.id}>
                      <td style={{ fontWeight: 'bold', fontSize: '1.1rem' }}>
                        {getRankIcon(index)}
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <Users size={16} color="var(--gray-color)" />
                          <span>{user.username || `User ${user.userId}`}</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <TrendingUp size={16} color="var(--primary-color)" />
                          <span style={{ fontWeight: 'bold' }}>{user.level}</span>
                        </div>
                      </td>
                      <td>{user.xp.toLocaleString()}</td>
                      <td>{user.messages}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '5px' }}>
                          {user.badges && user.badges.map((badge, badgeIndex) => (
                            <span key={badgeIndex} title={badge.name}>
                              {badge.emoji}
                            </span>
                          ))}
                          {(!user.badges || user.badges.length === 0) && (
                            <span style={{ color: 'var(--gray-color)' }}>No badges</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>Available Badges</h3>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '15px' }}>
          {availableBadges.map((badge) => (
            <div
              key={badge.id}
              style={{
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '15px',
                backgroundColor: '#f9fafb',
                textAlign: 'center'
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: '10px' }}>
                {badge.emoji}
              </div>
              <div style={{ fontWeight: 'bold', marginBottom: '5px' }}>
                {badge.name}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default Leveling