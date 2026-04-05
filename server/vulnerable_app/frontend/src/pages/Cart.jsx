import React, { useEffect, useState } from 'react'

export default function Cart() {
  const [cart, setCart] = useState(null)
  const token = localStorage.getItem('token')

  const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }

  useEffect(() => {
    if (token) {
      fetch('/api/cart', { headers }).then(r => r.json()).then(setCart)
    }
  }, [])

  if (!token) return <p style={{ margin: 20 }}>Please login first.</p>

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>Shopping Cart</h2>
      {cart && cart.items && cart.items.length > 0 ? (
        <div>
          {cart.items.map(item => (
            <div key={item.id} style={{ border: '1px solid #ddd', padding: 12, margin: '8px 0', borderRadius: 8, background: '#fff' }}>
              <strong>{item.name}</strong> x{item.quantity} = ${item.line_total?.toFixed(2)}
            </div>
          ))}
          <p style={{ fontWeight: 'bold', marginTop: 16 }}>Subtotal: ${cart.subtotal?.toFixed(2)}</p>
        </div>
      ) : <p>Cart is empty.</p>}
    </div>
  )
}
