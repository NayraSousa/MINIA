import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Login from './Login'
import Register from './Register'
import Dashboard from './Dashboard'
import RecruiterDashboard from './RecruiterDashboard'
import './App.css'

function App(){
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Login/>} />
        <Route path="/register" element={<Register/>} />
        <Route path="/dashboard" element={<Dashboard/>} />
        <Route path="/recruiter" element={<RecruiterDashboard/>} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
