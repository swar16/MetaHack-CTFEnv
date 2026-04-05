import React from 'react'

/**
 * ReviewCard Component
 *
 * VULNERABILITY: DOM-based XSS via dangerouslySetInnerHTML (CWE-79)
 * Review body is rendered as raw HTML, allowing stored XSS payloads
 * to execute in the browser.
 */
export default function ReviewCard({ review }) {
  const cardStyle = {
    border: '1px solid #ddd',
    borderRadius: '8px',
    padding: '12px',
    marginBottom: '10px',
    background: '#fff'
  }

  return (
    <div style={cardStyle}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <strong>{review.username || 'Anonymous'}</strong>
        <span>{'★'.repeat(review.rating || 0)}{'☆'.repeat(5 - (review.rating || 0))}</span>
      </div>
      {/* VULNERABILITY: dangerouslySetInnerHTML renders XSS payloads */}
      <div
        style={{ marginTop: '8px', color: '#555' }}
        dangerouslySetInnerHTML={{ __html: review.body }}
      />
      <small style={{ color: '#999' }}>{review.created_at}</small>
    </div>
  )
}
