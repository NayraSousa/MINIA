import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './login.css'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(false)
  const navigate = useNavigate()

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('http://localhost:3333/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ login: email, password })
      })

      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Erro ao autenticar')
        setLoading(false)
        return
      }

      // salvar token e usuário
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user))
      setSuccess(true)
      // redireciona para dashboard
      navigate('/dashboard')
    } catch (err) {
      setError('Falha na conexão com o servidor')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-root">
      <div className="left-panel">
        <h1 className="brand">MINIA RH</h1>
        <p className="subtitle">Recrutamento inteligente com apoio de Inteligência Artificial.</p>

        <div className="feature">
          <h4>Análise automática de currículos</h4>
          <p>A IA identifica habilidades e experiência relevantes para cada vaga.</p>
        </div>

        <div className="feature">
          <h4>Ranking de candidatos</h4>
          <p>Compare candidatos rapidamente com base em compatibilidade.</p>
        </div>

        <div className="feature">
          <h4>Decisões mais rápidas</h4>
          <p>Reduza o tempo de triagem e encontre o candidato ideal.</p>
        </div>
      </div>

      <div className="right-panel">
        <h2>Entrar</h2>
        <form className="login-form" onSubmit={handleSubmit}>
          <label>Login ou Email</label>
          <input
            type="text"
            placeholder="seu usuário ou email"
            value={email}
            onChange={e => setEmail(e.target.value)}
            required
          />

          <label>Senha</label>
          <input
            type="password"
            placeholder="********"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
          />

          <button className="primary" type="submit" disabled={loading}>
            {loading ? 'Entrando...' : 'Entrar'}
          </button>

          {error && <div className="error">{error}</div>}
          {success && <div className="success">Login realizado com sucesso.</div>}

          <p className="signup">Não possui conta? <a href="#">Criar conta</a></p>
        </form>
      </div>
    </div>
  )
}
