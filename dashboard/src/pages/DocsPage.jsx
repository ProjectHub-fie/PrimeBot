import React from 'react'
import { Link } from 'react-router-dom'

function DocsPage() {
  return (
    <div className="docs-page">
      <div className="container">
        <div style={{ padding: '40px 0', maxWidth: '800px', margin: '0 auto' }}>
          <h1 style={{ color: '#2C2F33', marginBottom: '20px' }}>PrimeBot Documentation</h1>
          <p style={{ color: '#6c757d', marginBottom: '30px' }}>
            Complete guide to using PrimeBot features and commands.
          </p>
          
          <div style={{ marginBottom: '30px' }}>
            <Link to="/" style={{ 
              color: '#5865F2', 
              textDecoration: 'none', 
              fontSize: '14px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px'
            }}>
              ← Back to Home
            </Link>
          </div>

          <div className="docs-content" style={{ lineHeight: '1.8' }}>
            <section style={{ marginBottom: '40px' }}>
              <h2 style={{ color: '#2C2F33', borderBottom: '2px solid #5865F2', paddingBottom: '10px', marginBottom: '20px' }}>Getting Started</h2>
              <p>Invite PrimeBot to your server and start using its powerful features right away.</p>
              <ol>
                <li>Click the "Add to Discord" button on our homepage</li>
                <li>Select your server and grant necessary permissions</li>
                <li>Start using commands with the prefix <code>$</code></li>
              </ol>
            </section>

            <section style={{ marginBottom: '40px' }}>
              <h2 style={{ color: '#2C2F33', borderBottom: '2px solid #5865F2', paddingBottom: '10px', marginBottom: '20px' }}>Commands</h2>
              
              <div style={{ marginBottom: '30px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>General Commands</h3>
                <ul style={{ paddingLeft: '20px' }}>
                  <li><strong>$help</strong> - Display all available commands</li>
                  <li><strong>$about</strong> - Information about the bot</li>
                  <li><strong>$echo [message]</strong> - Make the bot repeat your message</li>
                </ul>
              </div>

              <div style={{ marginBottom: '30px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>Giveaway Commands</h3>
                <ul style={{ paddingLeft: '20px' }}>
                  <li><strong>$giveaway</strong> - Create a new giveaway</li>
                  <li><strong>$end [messageId]</strong> - End a giveaway early</li>
                  <li><strong>$reroll [messageId]</strong> - Reroll giveaway winners</li>
                </ul>
              </div>

              <div style={{ marginBottom: '30px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>Leveling System</h3>
                <ul style={{ paddingLeft: '20px' }}>
                  <li><strong>$level</strong> - Check your current level</li>
                  <li><strong>$leaderboard</strong> - View server leaderboard</li>
                  <li><strong>$badges</strong> - View available badges</li>
                </ul>
              </div>
            </section>

            <section style={{ marginBottom: '40px' }}>
              <h2 style={{ color: '#2C2F33', borderBottom: '2px solid #5865F2', paddingBottom: '10px', marginBottom: '20px' }}>Features</h2>
              
              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>Giveaway System</h3>
                <p>Create engaging giveaways with customizable duration, prizes, and winner counts. Automatic winner selection and notification system.</p>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>Leveling & XP</h3>
                <p>Automatic XP tracking for active members. Customizable level roles and achievements to keep your community engaged.</p>
              </div>

              <div style={{ marginBottom: '20px' }}>
                <h3 style={{ color: '#404EED', marginBottom: '10px' }}>Poll System</h3>
                <p>Create interactive polls with multiple options. Real-time vote tracking and results display.</p>
              </div>
            </section>

            <section>
              <h2 style={{ color: '#2C2F33', borderBottom: '2px solid #5865F2', paddingBottom: '10px', marginBottom: '20px' }}>Support</h2>
              <p>Need help? Join our support server or check out the FAQ section.</p>
              <div style={{ marginTop: '20px' }}>
                <a href="https://discord.gg/gd7UNSfX86" 
                   target="_blank" 
                   rel="noopener noreferrer"
                   style={{ 
                     color: '#ffffff',
                     backgroundColor: '#5865F2',
                     padding: '12px 24px',
                     borderRadius: '4px',
                     textDecoration: 'none',
                     fontWeight: 'bold',
                     display: 'inline-block',
                     marginRight: '10px'
                   }}>
                  Join Support Server
                </a>
                <Link to="/faq"
                      style={{ 
                        color: '#5865F2',
                        border: '2px solid #5865F2',
                        padding: '12px 24px',
                        borderRadius: '4px',
                        textDecoration: 'none',
                        fontWeight: 'bold',
                        display: 'inline-block'
                      }}>
                  View FAQ
                </Link>
              </div>
            </section>
          </div>
        </div>
      </div>
    </div>
  )
}

export default DocsPage