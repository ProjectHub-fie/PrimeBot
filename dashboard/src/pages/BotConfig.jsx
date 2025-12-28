import React, { useState, useEffect } from 'react'
import { Save, RefreshCw } from 'lucide-react'

const BotConfig = () => {
  const [config, setConfig] = useState({
    prefix: '$',
    welcomeEnabled: true,
    welcomeMessage: 'Welcome to the server, {member}! Enjoy your stay!',
    dmWelcome: true,
    levelingEnabled: true,
    xpPerMessage: 15,
    xpCooldown: 60,
    giveawayEmoji: '🎉'
  })
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target
    setConfig(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  const handleSave = async () => {
    setLoading(true)
    setMessage('')
    
    try {
      const response = await fetch('/api/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
      })
      
      if (response.ok) {
        setMessage('Configuration saved successfully!')
      } else {
        setMessage('Failed to save configuration')
      }
    } catch (error) {
      setMessage('Error saving configuration')
      console.error('Error:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 style={{ marginBottom: '30px' }}>Bot Configuration</h1>

      {message && (
        <div className={`alert ${message.includes('success') ? 'alert-success' : 'alert-error'}`}>
          {message}
        </div>
      )}

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>General Settings</h3>
        
        <div className="form-group">
          <label className="form-label">Command Prefix</label>
          <input
            type="text"
            name="prefix"
            value={config.prefix}
            onChange={handleInputChange}
            className="form-input"
            style={{ maxWidth: '100px' }}
          />
          <small style={{ color: 'var(--gray-color)' }}>
            The prefix used for text commands (e.g., $help)
          </small>
        </div>

        <div className="form-group">
          <label className="form-label">Giveaway Reaction Emoji</label>
          <input
            type="text"
            name="giveawayEmoji"
            value={config.giveawayEmoji}
            onChange={handleInputChange}
            className="form-input"
            style={{ maxWidth: '100px' }}
          />
          <small style={{ color: 'var(--gray-color)' }}>
            Emoji used for giveaway reactions
          </small>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>Welcome System</h3>
        
        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              name="welcomeEnabled"
              checked={config.welcomeEnabled}
              onChange={handleInputChange}
            />
            Enable Welcome Messages
          </label>
        </div>

        <div className="form-group">
          <label className="form-label">Welcome Message</label>
          <textarea
            name="welcomeMessage"
            value={config.welcomeMessage}
            onChange={handleInputChange}
            className="form-textarea"
            rows="3"
            placeholder="Use {member} for mention, {username} for name, {server} for server name"
          />
        </div>

        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              name="dmWelcome"
              checked={config.dmWelcome}
              onChange={handleInputChange}
            />
            Send Welcome DM to New Members
          </label>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginBottom: '20px' }}>Leveling System</h3>
        
        <div className="form-group">
          <label style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <input
              type="checkbox"
              name="levelingEnabled"
              checked={config.levelingEnabled}
              onChange={handleInputChange}
            />
            Enable Leveling System
          </label>
        </div>

        <div className="form-group">
          <label className="form-label">XP Per Message</label>
          <input
            type="number"
            name="xpPerMessage"
            value={config.xpPerMessage}
            onChange={handleInputChange}
            className="form-input"
            min="1"
            max="100"
            style={{ maxWidth: '150px' }}
          />
          <small style={{ color: 'var(--gray-color)' }}>
            Base XP earned per message (1-100)
          </small>
        </div>

        <div className="form-group">
          <label className="form-label">XP Cooldown (seconds)</label>
          <input
            type="number"
            name="xpCooldown"
            value={config.xpCooldown}
            onChange={handleInputChange}
            className="form-input"
            min="10"
            max="300"
            style={{ maxWidth: '150px' }}
          />
          <small style={{ color: 'var(--gray-color)' }}>
            Cooldown between XP gains (10-300 seconds)
          </small>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '10px', marginTop: '20px' }}>
        <button
          onClick={handleSave}
          disabled={loading}
          className="btn btn-primary"
        >
          {loading ? <RefreshCw size={16} className="spinning" /> : <Save size={16} />}
          {loading ? 'Saving...' : 'Save Configuration'}
        </button>
      </div>
    </div>
  )
}

export default BotConfig