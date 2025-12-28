import React, { useState, useEffect } from 'react'
import { Vote, Plus, Users, Clock } from 'lucide-react'

const Polls = () => {
  const [polls, setPolls] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [newPoll, setNewPoll] = useState({
    question: '',
    options: ['', ''],
    duration: '24h',
    type: 'regular'
  })

  useEffect(() => {
    fetchPolls()
  }, [])

  const fetchPolls = async () => {
    try {
      const response = await fetch('/api/polls')
      if (response.ok) {
        const data = await response.json()
        setPolls(data)
      }
    } catch (error) {
      console.error('Error fetching polls:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleCreatePoll = async (e) => {
    e.preventDefault()
    setCreating(true)
    
    try {
      const response = await fetch('/api/polls', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newPoll)
      })
      
      if (response.ok) {
        await fetchPolls()
        setShowCreateForm(false)
        setNewPoll({ question: '', options: ['', ''], duration: '24h', type: 'regular' })
      }
    } catch (error) {
      console.error('Error creating poll:', error)
    } finally {
      setCreating(false)
    }
  }

  const addOption = () => {
    if (newPoll.options.length < 5) {
      setNewPoll(prev => ({
        ...prev,
        options: [...prev.options, '']
      }))
    }
  }

  const removeOption = (index) => {
    if (newPoll.options.length > 2) {
      setNewPoll(prev => ({
        ...prev,
        options: prev.options.filter((_, i) => i !== index)
      }))
    }
  }

  const updateOption = (index, value) => {
    setNewPoll(prev => ({
      ...prev,
      options: prev.options.map((option, i) => i === index ? value : option)
    }))
  }

  const endPoll = async (pollId) => {
    try {
      const response = await fetch(`/api/polls/${pollId}/end`, {
        method: 'POST'
      })
      
      if (response.ok) {
        await fetchPolls()
      }
    } catch (error) {
      console.error('Error ending poll:', error)
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
        <h1>Poll Management</h1>
        <button
          onClick={() => setShowCreateForm(true)}
          className="btn btn-primary"
        >
          <Plus size={16} />
          Create Poll
        </button>
      </div>

      {showCreateForm && (
        <div className="card" style={{ marginBottom: '30px' }}>
          <h3 style={{ marginBottom: '20px' }}>Create New Poll</h3>
          
          <form onSubmit={handleCreatePoll}>
            <div className="form-group">
              <label className="form-label">Poll Type</label>
              <select
                value={newPoll.type}
                onChange={(e) => setNewPoll(prev => ({ ...prev, type: e.target.value }))}
                className="form-select"
              >
                <option value="regular">Regular Poll (Reactions)</option>
                <option value="live">Live Poll (Buttons)</option>
              </select>
            </div>

            <div className="form-group">
              <label className="form-label">Question</label>
              <input
                type="text"
                value={newPoll.question}
                onChange={(e) => setNewPoll(prev => ({ ...prev, question: e.target.value }))}
                className="form-input"
                required
                placeholder="What would you like to ask?"
              />
            </div>

            <div className="form-group">
              <label className="form-label">Options</label>
              {newPoll.options.map((option, index) => (
                <div key={index} style={{ display: 'flex', gap: '10px', marginBottom: '10px' }}>
                  <input
                    type="text"
                    value={option}
                    onChange={(e) => updateOption(index, e.target.value)}
                    className="form-input"
                    placeholder={`Option ${index + 1}`}
                    required
                  />
                  {newPoll.options.length > 2 && (
                    <button
                      type="button"
                      onClick={() => removeOption(index)}
                      className="btn btn-danger"
                      style={{ padding: '8px 12px' }}
                    >
                      Remove
                    </button>
                  )}
                </div>
              ))}
              
              {newPoll.options.length < 5 && (
                <button
                  type="button"
                  onClick={addOption}
                  className="btn btn-secondary"
                  style={{ marginTop: '10px' }}
                >
                  Add Option
                </button>
              )}
            </div>

            <div className="form-group">
              <label className="form-label">Duration</label>
              <select
                value={newPoll.duration}
                onChange={(e) => setNewPoll(prev => ({ ...prev, duration: e.target.value }))}
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

            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="submit" disabled={creating} className="btn btn-primary">
                {creating ? 'Creating...' : 'Create Poll'}
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
          <h3 style={{ marginBottom: '20px' }}>Active Polls</h3>
          
          {polls.length === 0 ? (
            <p style={{ textAlign: 'center', color: 'var(--gray-color)', padding: '40px' }}>
              No polls found. Create your first poll to get started!
            </p>
          ) : (
            <div style={{ display: 'grid', gap: '15px' }}>
              {polls.map((poll) => (
                <div
                  key={poll.id}
                  style={{
                    border: '1px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '20px',
                    backgroundColor: '#f9fafb'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '15px' }}>
                    <div style={{ flex: 1 }}>
                      <h4 style={{ marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Vote size={20} color="var(--primary-color)" />
                        {poll.question}
                      </h4>
                      
                      <div style={{ display: 'flex', gap: '20px', marginBottom: '15px', fontSize: '0.9rem', color: 'var(--gray-color)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Users size={16} />
                          {poll.totalVotes || 0} votes
                        </span>
                        <span style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Clock size={16} />
                          {formatTimeRemaining(poll.endTime)}
                        </span>
                        <span style={{ 
                          padding: '2px 8px', 
                          borderRadius: '12px', 
                          fontSize: '0.8rem',
                          backgroundColor: poll.type === 'live' ? 'var(--success-color)' : 'var(--primary-color)',
                          color: 'white'
                        }}>
                          {poll.type === 'live' ? 'Live Poll' : 'Regular Poll'}
                        </span>
                      </div>
                    </div>
                    
                    {!poll.ended && (
                      <button
                        onClick={() => endPoll(poll.id)}
                        className="btn btn-warning"
                        style={{ fontSize: '0.8rem', padding: '8px 12px' }}
                      >
                        End Poll
                      </button>
                    )}
                  </div>
                  
                  <div style={{ display: 'grid', gap: '8px' }}>
                    {poll.options && poll.options.map((option, index) => {
                      const percentage = poll.totalVotes > 0 ? (option.votes / poll.totalVotes * 100) : 0
                      
                      return (
                        <div key={index} style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: '10px',
                          padding: '8px',
                          borderRadius: '6px',
                          backgroundColor: 'white',
                          border: '1px solid var(--border-color)'
                        }}>
                          <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '10px' }}>
                            <span>{option.text}</span>
                            <div style={{ 
                              flex: 1, 
                              height: '8px', 
                              backgroundColor: '#f3f4f6', 
                              borderRadius: '4px',
                              overflow: 'hidden'
                            }}>
                              <div style={{
                                height: '100%',
                                width: `${percentage}%`,
                                backgroundColor: 'var(--primary-color)',
                                transition: 'width 0.3s ease'
                              }} />
                            </div>
                          </div>
                          <span style={{ fontWeight: 'bold', minWidth: '50px', textAlign: 'right' }}>
                            {option.votes || 0} ({percentage.toFixed(1)}%)
                          </span>
                        </div>
                      )
                    })}
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

export default Polls