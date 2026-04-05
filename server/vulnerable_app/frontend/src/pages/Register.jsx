import React, { useState } from 'react'

export default function Register() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [email, setEmail] = useState('')
  const [result, setResult] = useState(null)

  const handleRegister = async (e) => {
    e.preventDefault()
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, email })
    })
    const data = await res.json()
    setResult(data)
    if (data.token) localStorage.setItem('token', data.token)
  }

  return (
    <div style={{ maxWidth: 400, margin: '40px auto' }}>
      <h2>Register</h2>
      <form onSubmit={handleRegister}>
        <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)}
          style={{ display: 'block', width: '100%', padding: 8, margin: '8px 0' }} />
        <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)}
          style={{ display: 'block', width: '100%', padding: 8, margin: '8px 0' }} />
        <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)}
          style={{ display: 'block', width: '100%', padding: 8, margin: '8px 0' }} />
        <button type="submit" style={{ padding: '8px 20px', background: '#1a1a2e', color: '#fff', border: 'none', cursor: 'pointer' }}>Register</button>
      </form>
      {result && <pre style={{ marginTop: 16, background: '#f0f0f0', padding: 12, overflow: 'auto' }}>{JSON.stringify(result, null, 2)}</pre>}
    </div>
  )
}
