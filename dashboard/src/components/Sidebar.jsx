import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  Home, 
  Settings, 
  Gift, 
  TrendingUp, 
  Vote, 
  MessageSquare, 
  Shield,
  LogOut
} from 'lucide-react'

const Sidebar = ({ user }) => {
  const location = useLocation()

  const handleLogout = () => {
    window.location.href = '/api/logout'
  }

  const menuItems = [
    { path: '/', icon: Home, label: 'Dashboard', description: 'Bot overview' },
    { path: '/config', icon: Settings, label: 'Bot Config', description: 'General settings' },
    { path: '/giveaways', icon: Gift, label: 'Giveaways', description: 'Manage giveaways' },
    { path: '/leveling', icon: TrendingUp, label: 'Leveling', description: 'XP and badges' },
    { path: '/polls', icon: Vote, label: 'Polls', description: 'Polling system' },
    { path: '/tickets', icon: MessageSquare, label: 'Tickets', description: 'Support tickets' },
    { path: '/moderation', icon: Shield, label: 'Moderation', description: 'Server moderation' }
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-header" style={{ marginBottom: '30px' }}>
        <h2 style={{ color: 'var(--primary-color)', fontSize: '1.5rem', fontWeight: 'bold' }}>
          Bot Dashboard
        </h2>
        <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
          Control and configure your Discord bot
        </p>
      </div>

      {user && (
        <div className="user-info" style={{ marginBottom: '20px', padding: '12px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {user.profileImageUrl && (
              <img 
                src={user.profileImageUrl} 
                alt="Profile" 
                style={{ 
                  width: '40px', 
                  height: '40px', 
                  borderRadius: '50%', 
                  objectFit: 'cover' 
                }} 
              />
            )}
            <div>
              <div style={{ fontWeight: '500', fontSize: '0.9rem' }}>
                {user.firstName} {user.lastName}
              </div>
              <div style={{ color: 'var(--gray-color)', fontSize: '0.8rem' }}>
                {user.email}
              </div>
            </div>
          </div>
        </div>
      )}

      <nav>
        {menuItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path

          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={20} />
              <div>
                <div style={{ fontWeight: '500' }}>{item.label}</div>
                <div style={{ fontSize: '0.8rem', opacity: '0.7' }}>{item.description}</div>
              </div>
            </Link>
          )
        })}
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: '20px', borderTop: '1px solid var(--border-color)' }}>
        <button 
          onClick={handleLogout}
          className="nav-item logout-btn"
          style={{ 
            width: '100%', 
            background: 'none', 
            border: 'none', 
            padding: '12px', 
            display: 'flex', 
            alignItems: 'center', 
            gap: '12px',
            color: '#dc3545',
            cursor: 'pointer',
            borderRadius: '8px',
            marginBottom: '10px'
          }}
        >
          <LogOut size={20} />
          <div>
            <div style={{ fontWeight: '500' }}>Logout</div>
            <div style={{ fontSize: '0.8rem', opacity: '0.7' }}>Sign out of dashboard</div>
          </div>
        </button>
        <div style={{ fontSize: '0.8rem', color: 'var(--gray-color)' }}>
          Discord Bot v2.5.0
        </div>
      </div>
    </aside>
  )
}

export default Sidebar