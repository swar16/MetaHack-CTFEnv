import React from 'react'
import { Link } from 'react-router-dom'

const navStyle = {
  background: '#1a1a2e',
  padding: '12px 20px',
  display: 'flex',
  gap: '16px',
  alignItems: 'center'
}

const linkStyle = {
  color: '#e0e0e0',
  textDecoration: 'none',
  fontSize: '14px'
}

const brandStyle = {
  color: '#fff',
  fontWeight: 'bold',
  fontSize: '18px',
  textDecoration: 'none',
  marginRight: '20px'
}

export default function Navbar() {
  return (
    <nav style={navStyle}>
      <Link to="/" style={brandStyle}>VulnShop</Link>
      <Link to="/products" style={linkStyle}>Products</Link>
      <Link to="/search" style={linkStyle}>Search</Link>
      <Link to="/cart" style={linkStyle}>Cart</Link>
      <Link to="/messages" style={linkStyle}>Messages</Link>
      <Link to="/profile" style={linkStyle}>Profile</Link>
      <Link to="/admin" style={linkStyle}>Admin</Link>
      <Link to="/login" style={linkStyle}>Login</Link>
      <Link to="/register" style={linkStyle}>Register</Link>
    </nav>
  )
}
