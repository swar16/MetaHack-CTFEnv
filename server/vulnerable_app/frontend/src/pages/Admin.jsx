import React, { useEffect, useState } from 'react'

export default function Admin() {
  const [dashboard, setDashboard] = useState(null)
  const token = localStorage.getItem('token')

  useEffect(() => {
    if (token) {
      fetch('/api/admin/dashboard', { headers: { Authorization: `Bearer ${token}` } })
        .then(r => r.json()).then(setDashboard)
    }
  }, [])

  if (!token) return <p style={{ margin: 20 }}>Please login first.</p>

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>Admin Dashboard</h2>
      {dashboard ? (
        <div style={{ background: '#fff', padding: 20, borderRadius: 8, border: '1px solid #ddd' }}>
          <pre>{JSON.stringify(dashboard, null, 2)}</pre>
        </div>
      ) : <p>Loading...</p>}
    </div>
  )
}
