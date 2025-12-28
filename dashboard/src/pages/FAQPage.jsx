import React from 'react'
import { Link } from 'react-router-dom'

function FAQPage() {
  const faqs = [
    {
      question: "How can I invite PrimeBot to my server?",
      answer: "Click the 'Add to Discord' button on our homepage and follow the authorization process. Make sure to grant the necessary permissions for the bot to function properly."
    },
    {
      question: "What permissions does PrimeBot need?",
      answer: "PrimeBot requires permissions to read messages, send messages, manage messages, add reactions, and use external emojis. Administrator permission is recommended for full functionality."
    },
    {
      question: "How do I create a giveaway?",
      answer: "Use the $giveaway command followed by the setup process. The bot will guide you through setting the prize, duration, and number of winners."
    },
    {
      question: "Can I customize the bot's prefix?",
      answer: "Currently, PrimeBot uses the $ prefix. Custom prefix functionality may be added in future updates."
    },
    {
      question: "How does the leveling system work?",
      answer: "Members gain XP by sending messages in your server. The more active they are, the higher their level becomes. You can view rankings with the $leaderboard command."
    },
    {
      question: "Is PrimeBot free to use?",
      answer: "Yes! PrimeBot is completely free to use with all features available at no cost."
    },
    {
      question: "How do I report bugs or request features?",
      answer: "Join our support server using the link in the footer, or use the contact information provided there to report issues or suggest new features."
    },
    {
      question: "Can I use PrimeBot in multiple servers?",
      answer: "Yes, you can invite PrimeBot to as many servers as you'd like. Each server's data is kept separate and secure."
    },
    {
      question: "What happens to my data if I remove the bot?",
      answer: "When you remove PrimeBot from your server, all associated data (levels, giveaways, etc.) is automatically removed to protect your privacy."
    },
    {
      question: "How can I get support?",
      answer: "Join our support Discord server for real-time help from our community and support team. You can also check our documentation for detailed guides."
    }
  ]

  return (
    <div className="faq-page">
      <div className="container">
        <div style={{ padding: '40px 0', maxWidth: '800px', margin: '0 auto' }}>
          <h1 style={{ color: '#2C2F33', marginBottom: '20px' }}>Frequently Asked Questions</h1>
          <p style={{ color: '#6c757d', marginBottom: '30px' }}>
            Find answers to common questions about PrimeBot.
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

          <div className="faq-content">
            {faqs.map((faq, index) => (
              <div key={index} style={{
                backgroundColor: '#ffffff',
                border: '1px solid #e5e7eb',
                borderRadius: '8px',
                padding: '20px',
                marginBottom: '20px',
                boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
              }}>
                <h3 style={{ 
                  color: '#2C2F33', 
                  marginBottom: '15px',
                  fontSize: '1.2rem',
                  fontWeight: '600'
                }}>
                  Q: {faq.question}
                </h3>
                <p style={{ 
                  color: '#6c757d', 
                  lineHeight: '1.6',
                  margin: '0'
                }}>
                  A: {faq.answer}
                </p>
              </div>
            ))}
          </div>

          <div style={{ 
            backgroundColor: '#f8f9fa',
            padding: '30px',
            borderRadius: '8px',
            textAlign: 'center',
            marginTop: '40px'
          }}>
            <h3 style={{ color: '#2C2F33', marginBottom: '15px' }}>Still have questions?</h3>
            <p style={{ color: '#6c757d', marginBottom: '20px' }}>
              Join our support server for personalized help from our community.
            </p>
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
                 display: 'inline-block'
               }}>
              Join Support Server
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}

export default FAQPage