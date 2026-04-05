import React from 'react'
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom'
import Login from './pages/Login'
import Register from './pages/Register'
import Products from './pages/Products'
import ProductDetail from './pages/ProductDetail'
import Cart from './pages/Cart'
import Profile from './pages/Profile'
import Admin from './pages/Admin'
import Search from './pages/Search'
import Messages from './pages/Messages'
import Navbar from './components/Navbar'

const appStyle = {
  maxWidth: '960px',
  margin: '0 auto',
  padding: '20px'
}

export default function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <div style={appStyle}>
        <Routes>
          <Route path="/" element={<Products />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/products" element={<Products />} />
          <Route path="/products/:id" element={<ProductDetail />} />
          <Route path="/cart" element={<Cart />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/admin" element={<Admin />} />
          <Route path="/search" element={<Search />} />
          <Route path="/messages" element={<Messages />} />
        </Routes>
      </div>
    </BrowserRouter>
  )
}
