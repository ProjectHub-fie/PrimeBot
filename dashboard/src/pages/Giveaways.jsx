import React, { useState, useEffect } from 'react'
import { Plus, Gift, Users, Clock, RotateCcw } from 'lucide-react'

const Giveaways = () => {
  const [giveaways, setGiveaways] = useState([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [newGiveaway, setNewGiveaway] = useState({
    prize: '',
    duration: '24h',
    winners: 1,
    description: ''
  })

  useEffect(() => {
    fetchGiveaways()
  }, [])

  const fetchGiveaways = async () => {
    try {
      const response = await fetch('/api/giveaways')
      if (response.ok) {
        const data = await response.json()
        setGiveaways(data)
      }
    } catch (error) {
      console.error('Error fetching giveaways:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCreateGiveaway = async (e) => {
    e.preventDefault()
    setCreating(true)
    
    try {
      const response = await fetch('/api/giveaways', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newGiveaway)
      })
      
      if (response.ok) {
        await fetchGiveaways()
        setShowCreateForm(false)
        setNewGiveaway({ prize: '', duration: '24h', winners: 1, description: '' })
      }
    } catch (error) {
      console.error('Error creating giveaway:', error)
    } finally {
      setCreating(false)
    }
  }

  const handleEndGiveaway = async (giveawayId) => {
    try {
      const response = await fetch(`/api/giveaways/${giveawayId}/end`, {
        method: 'POST'
      })
      
      if (response.ok) {
        await fetchGiveaways()
      }
    } catch (error) {
      console.error('Error ending giveaway:', error)
    }
  }

  const handleReroll = async (giveawayId) => {
    try {
      const response = await fetch(`/api/giveaways/${giveawayId}/reroll`, {
        method: 'POST'
      })
      
      if (response.ok) {
        await fetchGiveaways()
      }
    } catch (error) {
      console.error('Error rerolling giveaway:', error)
    }
  }

  const formatTimeRemaining = (endTime) => {
    const now = new Date()
    const end = new Date(endTime)
    const diff = end - now
    
    if (diff <= 0) return 'Ended'
    
    const hours = Math.floor(diff / (1000 * 60 * 60))
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60))
    
    return `${hours}h ${minutes}m remaining`
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '30px' }}>
        <h1>Giveaway Management</h1>
        <button
          onClick={() => setShowCreateForm(true)}
          className="btn btn-primary"
        >
          <Plus size={16} />
          Create Giveaway
        </button>
      </div>

      {showCreateForm && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <h3 style={{ marginBottom: '20px' }}>Create New Giveaway</h3>
          
          <form onSubmit={handleCreateGiveaway}>
            <div className="form-group">
              <label className="form-label">Prize</label>
              <input
                type="text"
                value={newGiveaway.prize}
                onChange={(e) => setNewGiveaway(prev => ({ ...prev, prize: e.target.value }))}
                className="form-input"
                required
                placeholder="What are you giving away?"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Duration</label>
              <select
                value={newGiveaway.duration}
                onChange={(e) => setNewGiveaway(prev => ({ ...prev, duration: e.target.value }))}
                className="form-select"
              >
                <option value="1h">1 Hour</option>
                <option value="6h">6 Hours</option>
                <option value="12h">12 Hours</option>
                <option value="24h">24 Hours</option>
                <option value="48h">48 Hours</option>
                <option value="1w">1 Week</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Number of Winners</label>
              <input
                type="number"
                value={newGiveaway.winners}
                onChange={(e) => setNewGiveaway(prev => ({ ...prev, winners: parseInt(e.target.value) }))}
                className="form-input"
                min="1"
                max="10"
                style={{ maxWidth: '150px' }}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Description (Optional)</label>
              <textarea
                value={newGiveaway.description}
                onChange={(e) => setNewGiveaway(prev => ({ ...prev, description: e.target.value }))}
                className="form-textarea"
                rows="3"
                placeholder="Additional details about the giveaway..."
              />
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="submit" disabled={creating} className="btn btn-primary">
                {creating ? 'Creating...' : 'Create Giveaway'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreateForm(false)}
                className="btn btn-secondary"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
        </div>
      ) : (
        <div className="card">
          <h3 style={{ marginBottom: '20px' }}>Active Giveaways</h3>
          
          {giveaways.length === 0 ? (
            <p style={{ textAlign: 'center', color: 'var(--gray-color)', padding: '40px' }}>
              No giveaways found. Create your first giveaway to get started!
            </p>
          ) : (
            <div style={{ display: 'grid', gap: '15px' }}>
              {giveaways.map((giveaway) => (
                <div
                  key={giveaway.id}
                  style={{
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '20px',
                    backgroundColor: '#f9fafb'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                    <div style={{ flex: 1 }}>
                      <h4 style={{ marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Gift size={20} color="var(--primary-color)" />
                        {giveaway.prize}
                      </h4>
                      
                      <div style={{ display: 'flex', gap: '20px', marginBottom: '10px', fontSize: '0.9rem', color: 'var(--gray-color)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Users size={16} />
                          {giveaway.participants || 0} participants
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Clock size={16} />
                          {formatTimeRemaining(giveaway.endTime)}
                        </span>
                      </div>
                      
                      {giveaway.description && (
                        <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                          {giveaway.description}
                        </p>
                      )}
                    </div>
                    
                    <div style={{ display: 'flex', gap: '10px' }}>
                      {!giveaway.ended && (
                        <button
                          onClick={() => handleEndGiveaway(giveaway.id)}
                          className="btn btn-warning"
                          style={{ fontSize: '0.8rem', padding: '8px 12px' }}
                        >
                          End Now
                        </button>
                      )}
                      
                      {giveaway.ended && (
                        <button
                          onClick={() => handleReroll(giveaway.id)}
                          className="btn btn-primary"
                          style={{ fontSize: '0.8rem', padding: '8px 12px' }}
                        >
                          <RotateCcw size={14} />
                          Reroll
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default Giveaways