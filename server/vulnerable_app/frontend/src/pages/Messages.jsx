import React, { useEffect, useState } from 'react'

export default function Messages() {
  const [messages, setMessages] = useState([])
  const [selected, setSelected] = useState(null)
  const token = localStorage.getItem('token')
  const headers = { Authorization: `Bearer ${token}` }

  useEffect(() => {
    if (token) {
      fetch('/api/messages', { headers }).then(r => r.json()).then(d => setMessages(d.messages || []))
    }
  }, [])

  const viewMessage = async (id) => {
    const res = await fetch(`/api/messages/${id}`, { headers })
    const data = await res.json()
    setSelected(data.message)
  }

  if (!token) return <p style={{ margin: 20 }}>Please login first.</p>

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>Messages</h2>
      <div style={{ display: 'flex', gap: 20 }}>
        <div style={{ flex: 1 }}>
          {messages.length === 0 ? <p>No messages.</p> :
            messages.map(m => (
              <div key={m.id} onClick={() => viewMessage(m.id)}
                style={{ padding: 12, border: '1px solid #ddd', margin: '4px 0', borderRadius: 4, cursor: 'pointer', background: '#fff' }}>
                <strong>{m.subject}</strong>
                <br /><small>From: {m.sender || 'System'}</small>
              </div>
            ))
          }
        </div>
        <div style={{ flex: 2 }}>
          {selected && (
            <div style={{ background: '#fff', padding: 16, borderRadius: 8, border: '1px solid #ddd' }}>
              <h3>{selected.subject}</h3>
              <p style={{ color: '#666' }}>From: {selected.sender_name || 'System'} | To: {selected.recipient_name}</p>
              <p style={{ marginTop: 12 }}>{selected.body}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
