import React, { useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'

/**
 * Search Page
 *
 * VULNERABILITY: DOM-based XSS (CWE-79)
 * Reads the 'q' query parameter from the URL and injects it
 * directly into the DOM via innerHTML without sanitization.
 */
export default function Search() {
  const [searchParams] = useSearchParams()
  const q = searchParams.get('q') || ''
  const resultRef = useRef(null)

  useEffect(() => {
    if (q && resultRef.current) {
      // VULNERABILITY: DOM XSS - user input injected via innerHTML (CWE-79)
      resultRef.current.innerHTML = `<p>Searching for: <strong>${q}</strong></p>`

      fetch(`/api/search?q=${encodeURIComponent(q)}`)
        .then(r => r.json())
        .then(data => {
          let html = `<h3>Results for: ${q}</h3>`
          if (data.products && data.products.length > 0) {
            html += '<ul>'
            data.products.forEach(p => { html += `<li>${p.name} - $${p.price}</li>` })
            html += '</ul>'
          } else {
            html += `<p>No results found for: ${q}</p>`
          }
          resultRef.current.innerHTML = html
        })
    }
  }, [q])

  return (
    <div style={{ margin: '20px 0' }}>
      <h2>Search Products</h2>
      <form method="get" action="/search" style={{ margin: '16px 0' }}>
        <input name="q" defaultValue={q} placeholder="Search..." style={{ padding: 8, width: 300 }} />
        <button type="submit" style={{ padding: '8px 16px', marginLeft: 8 }}>Search</button>
      </form>
      <div ref={resultRef} />
    </div>
  )
}
