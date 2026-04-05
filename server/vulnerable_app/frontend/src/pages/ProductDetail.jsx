import React, { useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import ReviewCard from '../components/ReviewCard'

export default function ProductDetail() {
  const { id } = useParams()
  const [product, setProduct] = useState(null)
  const [reviews, setReviews] = useState([])

  useEffect(() => {
    fetch(`/api/products/${id}`).then(r => r.json()).then(d => {
      setProduct(d.product)
      setReviews(d.reviews || [])
    })
  }, [id])

  if (!product) return <p>Loading...</p>

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>{product.name}</h2>
      <p style={{ color: '#666' }}>{product.description}</p>
      <p style={{ fontSize: 24, fontWeight: 'bold', color: '#1a1a2e' }}>${product.price}</p>
      <p><small>Category: {product.category} | Stock: {product.stock}</small></p>

      <h3 style={{ marginTop: 30 }}>Reviews</h3>
      {reviews.length === 0 ? <p>No reviews yet.</p> :
        reviews.map(r => <ReviewCard key={r.id} review={r} />)
      }
    </div>
  )
}
