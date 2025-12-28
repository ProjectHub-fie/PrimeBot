import React, { useState, useEffect } from 'react'
import { MessageSquare, User, Clock, X } from 'lucide-react'

const Tickets = () => {
  const [tickets, setTickets] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchTickets()
  }, [])

  const fetchTickets = async () => {
    try {
      const response = await fetch('/api/tickets')
      if (response.ok) {
        const data = await response.json()
        setTickets(data)
      }
    } catch (error) {
      console.error('Error fetching tickets:', error)
    } finally {
      setLoading(false)
    }
  }

  const closeTicket = async (ticketId) => {
    try {
      const response = await fetch(`/api/tickets/${ticketId}/close`, {
        method: 'POST'
      })
      
      if (response.ok) {
        await fetchTickets()
      }
    } catch (error) {
      console.error('Error closing ticket:', error)
    }
  }

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString()
  }

  const getStatusColor = (status) => {
    switch (status) {
      case 'open': return 'var(--success-color)'
      case 'closed': return 'var(--gray-color)'
      case 'pending': return 'var(--warning-color)'
      default: return 'var(--gray-color)'
    }
  }

  return (
    <div>
      <h1 style={{ marginBottom: '30px' }}>Ticket Management</h1>

      {loading ? (
        <div className="loading">
          <div className="spinner"></div>
        </div>
      ) : (
        <>
          <div className="stats-grid" style={{ marginBottom: '30px' }}>
            <div className="stat-card">
              <MessageSquare size={40} color="var(--primary-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--primary-color)' }}>
                {tickets.length}
              </div>
              <div className="stat-label">Total Tickets</div>
            </div>
            
            <div className="stat-card">
              <MessageSquare size={40} color="var(--success-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--success-color)' }}>
                {tickets.filter(t => t.status === 'open').length}
              </div>
              <div className="stat-label">Open Tickets</div>
            </div>
            
            <div className="stat-card">
              <MessageSquare size={40} color="var(--gray-color)" style={{ marginBottom: '10px' }} />
              <div className="stat-value" style={{ color: 'var(--gray-color)' }}>
                {tickets.filter(t => t.status === 'closed').length}
              </div>
              <div className="stat-label">Closed Tickets</div>
            </div>
          </div>

          <div className="card">
            <h3 style={{ marginBottom: '20px' }}>All Tickets</h3>
            
            {tickets.length === 0 ? (
              <p style={{ textAlign: 'center', color: 'var(--gray-color)', padding: '40px' }}>
                No tickets found. Tickets will appear here when users create them.
              </p>
            ) : (
              <div className="table-container" style={{ overflowX: 'auto' }}>
                <table className="table">
                  <thead>
                    <tr>
                      <th>Ticket ID</th>
                      <th>User</th>
                      <th>Subject</th>
                      <th>Status</th>
                      <th>Created</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tickets.map((ticket) => (
                      <tr key={ticket.id}>
                        <td>
                          <code style={{ 
                            backgroundColor: '#f3f4f6', 
                            padding: '2px 6px', 
                            borderRadius: '4px',
                            fontSize: '0.8rem'
                          }}>
                            #{ticket.id}
                          </code>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <User size={16} color="var(--gray-color)" />
                            <span>{ticket.username || `User ${ticket.userId}`}</span>
                          </div>
                        </td>
                        <td>
                          <div>
                            <div style={{ fontWeight: '500' }}>{ticket.subject}</div>
                            {ticket.description && (
                              <div style={{ 
                                fontSize: '0.8rem', 
                                color: 'var(--gray-color)',
                                maxWidth: '200px',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}>
                                {ticket.description}
                              </div>
                            )}
                          </div>
                        </td>
                        <td>
                          <span style={{
                            padding: '4px 8px',
                            borderRadius: '12px',
                            fontSize: '0.8rem',
                            fontWeight: '500',
                            backgroundColor: getStatusColor(ticket.status),
                            color: 'white'
                          }}>
                            {ticket.status.charAt(0).toUpperCase() + ticket.status.slice(1)}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                            <Clock size={14} color="var(--gray-color)" />
                            <span style={{ fontSize: '0.8rem' }}>
                              {formatDate(ticket.createdAt)}
                            </span>
                          </div>
                        </td>
                        <td>
                          {ticket.status === 'open' && (
                            <button
                              onClick={() => closeTicket(ticket.id)}
                              className="btn btn-danger"
                              style={{ fontSize: '0.8rem', padding: '6px 12px' }}
                            >
                              <X size={14} />
                              Close
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h3 style={{ marginBottom: '20px' }}>Ticket System Settings</h3>
            
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '20px' }}>
              <div>
                <h4>How Tickets Work</h4>
                <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                  Users can create tickets using the /ticket command. A private channel is created for each ticket.
                </p>
              </div>
              <div>
                <h4>Auto-Close</h4>
                <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                  Tickets can be manually closed by staff or automatically after a period of inactivity.
                </p>
              </div>
              <div>
                <h4>Categories</h4>
                <p style={{ color: 'var(--gray-color)', fontSize: '0.9rem' }}>
                  Support tickets are organized by category: General, Technical, Reports, and Other.
                </p>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default Tickets