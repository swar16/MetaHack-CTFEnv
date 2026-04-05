import React, { useEffect, useState } from 'react'

export default function Profile() {
  const [user, setUser] = useState(null)
  const token = localStorage.getItem('token')

  useEffect(() => {
    if (token) {
      fetch('/api/auth/me', { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.json()).then(d => setUser(d.user))
    }
  }, [])

  if (!token) return <p style={{ margin: 20 }}>Please login first.</p>

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>Profile</h2>
      {user ? (
        <div style={{ background: '#fff', padding: 20, borderRadius: 8, border: '1px solid #ddd' }}>
          <p><strong>Username:</strong> {user.username}</p>
          <p><strong>Email:</strong> {user.email}</p>
          <p><strong>Role:</strong> {user.role}</p>
          <p><strong>Balance:</strong> ${user.balance?.toFixed(2)}</p>
        </div>
      ) : <p>Loading...</p>}
    </div>
  )
}
