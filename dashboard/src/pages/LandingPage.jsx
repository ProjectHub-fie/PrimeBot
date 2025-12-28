import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

function LandingPage() {
  const [botStats, setBotStats] = useState({
    servers: 'Loading...',
    uptime: 'Loading...',
    commands: 'Loading...'
  })

  useEffect(() => {
    // Fetch bot statistics
    const fetchBotStats = async () => {
      try {
        const response = await fetch('/api/botinfo')
        const data = await response.json()
        setBotStats({
          servers: data.servers || 'N/A',
          uptime: data.uptime || 'N/A',
          commands: data.commands ? data.commands.length : 'N/A'
        })
      } catch (error) {
        console.error('Error fetching bot stats:', error)
        setBotStats({
          servers: 'Error',
          uptime: 'Error',
          commands: 'Error'
        })
      }
    }

    fetchBotStats()
    const interval = setInterval(fetchBotStats, 30000) // Update every 30 seconds

    return () => clearInterval(interval)
  }, [])

  return (
    <div className="landing-page">
      <header>
        <div className="container">
          <div className="logo">
            <img src="https://images-ext-1.discordapp.net/external/8_2-oV24CYGRGCBjvNcStL2gNz6VWKloGxcgp3dDRnw/https/cdn.discordapp.com/avatars/1356575287151951943/a_b68e32aef94163405d60d977abe16f69.gif" alt="Bot Logo" />
            <h1>PrimeBot</h1>
          </div>
          <nav className="desktop-nav">
            <ul>
              <li><a href="#features">Features</a></li>
              <li><a href="#commands">Commands</a></li>
              <li><Link to="/docs">Docs</Link></li>
              <li><Link to="/faq">FAQ</Link></li>
              <li><Link to="/dashboard" className="btn btn-dashboard">Dashboard</Link></li>
              <li><a href="#invite" className="btn">Invite Bot</a></li>
            </ul>
          </nav>
          <button className="mobile-menu-toggle" onClick={() => {
            const nav = document.querySelector('.mobile-nav');
            nav.style.display = nav.style.display === 'flex' ? 'none' : 'flex';
          }}>
            <i className="fas fa-bars"></i>
          </button>
          <nav className="mobile-nav">
            <ul>
              <li><a href="#features">Features</a></li>
              <li><a href="#commands">Commands</a></li>
              <li><Link to="/docs">Docs</Link></li>
              <li><Link to="/faq">FAQ</Link></li>
              <li><Link to="/dashboard" className="btn btn-dashboard">Dashboard</Link></li>
              <li><a href="#invite" className="btn">Invite Bot</a></li>
            </ul>
          </nav>
        </div>
      </header>

      <section className="hero">
        <div className="container">
          <h1>Boost Your Server with Awesome Features</h1>
          <p>A feature-rich Discord bot with multiple functions for smart servers</p>
          <div className="buttons">
            <a href="#invite" className="btn btn-primary">Add to Discord</a>
            <Link to="/dashboard" className="btn btn-dashboard">Dashboard</Link>
            <a href="#commands" className="btn btn-secondary">View Commands</a>
          </div>
        </div>
      </section>

      <section id="features" className="features">
        <div className="container">
          <h2>Features</h2>
          <div className="feature-grid">
            <div className="feature-card">
              <i className="fas fa-gift"></i>
              <h3>Easy Giveaways</h3>
              <p>Create giveaways with custom duration, prizes, and winner count</p>
            </div>
            <div className="feature-card">
              <i className="fas fa-redo"></i>
              <h3>Reroll Winners</h3>
              <p>Easily reroll winners if needed with a simple command</p>
            </div>
            <div className="feature-card">
              <i className="fas fa-bell"></i>
              <h3>Automatic Notifications</h3>
              <p>Participants and winners are automatically notified</p>
            </div>
            <div className="feature-card">
              <i className="fas fa-shield-alt"></i>
              <h3>Moderation Controls</h3>
              <p>Control who can create and manage giveaways on your server</p>
            </div>
            <div className="feature-card">
              <i className="fas fa-calendar-alt"></i>
              <h3>Scheduled Giveaways</h3>
              <p>Set giveaways to end at specific times or durations</p>
            </div>
            <div className="feature-card">
              <i className="fas fa-user-plus"></i>
              <h3>Welcome System</h3>
              <p>Greet new members with customizable welcome messages</p>
            </div>
          </div>
        </div>
      </section>

      <section id="commands" className="commands">
        <div className="container">
          <h2>Commands</h2>
          <div className="command-list">
            <div className="command-item">
              <h3><span className="prefix">$</span>help</h3>
              <p>Shows a list of available commands</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>commands</h3>
              <p>Shows a list of available commands (alias for help)</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>giveaway</h3>
              <p>Creates a new giveaway with customizable duration, prize, and winner count</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>gstart</h3>
              <p>Shortcut to create a giveaway</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>end</h3>
              <p>Ends a giveaway early and picks winners</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>gend</h3>
              <p>Shortcut to end a giveaway</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>reroll</h3>
              <p>Rerolls winners for a completed giveaway</p>
            </div>
            <div className="command-item">
              <h3><span className="prefix">$</span>echo</h3>
              <p>Makes the bot repeat a message</p>
            </div>
          </div>
        </div>
      </section>


      <section id="invite" className="invite">
        <div className="container">
          <h2>Ready to enhance your server?</h2>
          <p>Add the PrimeBot to your Discord server now!</p>
          <a href="https://discord.com/oauth2/authorize?client_id=1356575287151951943&permissions=8&integration_type=0&scope=bot%20applications.commands" className="btn btn-primary" target="_blank" rel="noopener noreferrer">
            <i className="fab fa-discord"></i> Add to Discord
          </a>
        </div>
      </section>

      <footer>
        <div className="container">
          <div className="footer-content">
            <div className="footer-logo">
              <img src="https://images-ext-1.discordapp.net/external/8_2-oV24CYGRGCBjvNcStL2gNz6VWKloGxcgp3dDRnw/https/cdn.discordapp.com/avatars/1356575287151951943/a_b68e32aef94163405d60d977abe16f69.gif" alt="Bot Logo" />
              <h3>PrimeBot</h3>
            </div>
            <div className="footer-links">
              <h4>Links</h4>
              <ul>
                <li><a href="#features">Features</a></li>
                <li><a href="#commands">Commands</a></li>
                <li><a href="#invite">Invite Bot</a></li>
              </ul>
            </div>
            <div className="footer-links">
              <h4>Support</h4>
              <ul>
                <li><a href="https://discord.gg/gd7UNSfX86" target="_blank" rel="noopener noreferrer">Support Server</a></li>
                <li><Link to="/docs">Documentation</Link></li>
                <li><Link to="/faq">FAQ</Link></li>
              </ul>
            </div>
          </div>
          <div className="footer-bottom">
            <p>&copy; 2025 <a href="https://projecthub-fie.vercel.app/" target="_blank" rel="noopener noreferrer">ProjectHub</a> All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default LandingPage