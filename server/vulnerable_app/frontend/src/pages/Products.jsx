import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'

export default function Products() {
  const [products, setProducts] = useState([])

  useEffect(() => {
    fetch('/api/products').then(r => r.json()).then(d => setProducts(d.products || []))
  }, [])

  return (
    <div>
      <h2 style={{ margin: '20px 0' }}>Products</h2>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: 16 }}>
        {products.map(p => (
          <Link to={`/products/${p.id}`} key={p.id} style={{ textDecoration: 'none', color: 'inherit' }}>
            <div style={{ border: '1px solid #ddd', borderRadius: 8, padding: 16, background: '#fff' }}>
              <h3>{p.name}</h3>
              <p style={{ color: '#666', fontSize: 14 }}>{p.description}</p>
              <p style={{ fontWeight: 'bold', color: '#1a1a2e' }}>${p.price}</p>
              <small style={{ color: '#999' }}>{p.category}</small>
            </div>
          </Link>
        ))}
      </div>
    </div>
  )
}
