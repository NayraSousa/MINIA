import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import './login.css'
import apiClient from './services/apiClient'

export default function Register() {
  const [form, setForm] = useState({
    name: '',
    email: '',
    login: '',
    password: '',
    role: 'candidate',
    linkedin_url: '',
    github_url: '',
    company_name: '',
    cnpj: '',
    department: '',
    position: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(false)
  const navigate = useNavigate()

  function setField(field, value){
    setForm(prev => ({ ...prev, [field]: value }))
  }

  async function handleSubmit(e){
    e.preventDefault()
    setError(null)

    if(!form.name.trim() || !form.email.trim() || !form.login.trim() || !form.password){
      setError('Preencha todos os campos obrigatórios')
      return
    }
    if(form.password.length < 6){
      setError('A senha deve ter pelo menos 6 caracteres')
      return
    }
    if(form.role === 'recruiter' && !form.cnpj.trim()){
      setError('Informe o CNPJ da empresa')
      return
    }

    const payload = {
      name: form.name.trim(),
      email: form.email.trim(),
      login: form.login.trim(),
      password: form.password,
      role: form.role
    }
    if(form.role === 'candidate'){
      payload.linkedin_url = form.linkedin_url.trim()
      payload.github_url = form.github_url.trim()
    }else{
      payload.company_name = form.company_name.trim()
      payload.cnpj = form.cnpj.replace(/\D/g, '')
      payload.department = form.department.trim()
      payload.position = form.position.trim()
    }

    setLoading(true)
    try{
      const { ok, data } = await apiClient.post('/user', payload)
      if(!ok){
        setError(data?.error || 'Erro ao criar conta')
        setLoading(false)
        return
      }

      setSuccess(true)
      setTimeout(() => navigate('/'), 1200)
    }catch{
      setError('Falha na conexão com o servidor')
    }finally{
      setLoading(false)
    }
  }

  return (
    <div className="login-root">
      <div className="left-panel">
        <h1 className="brand">MINIA RH</h1>
        <p className="subtitle">Crie sua conta e comece a usar recrutamento com IA.</p>

        <div className="feature">
          <h4>Candidatos</h4>
          <p>Cadastre seu perfil, compartilhe LinkedIn e GitHub e se candidate às vagas certas para você.</p>
        </div>

        <div className="feature">
          <h4>Recrutadores</h4>
          <p>Crie vagas, receba candidaturas e veja o ranking automático de compatibilidade por IA.</p>
        </div>

        <div className="feature">
          <h4>Sem complicação</h4>
          <p>Apenas os dados essenciais para você entrar em minutos.</p>
        </div>
      </div>

      <div className="right-panel">
        <h2>Criar conta</h2>
        <form className="login-form" onSubmit={handleSubmit}>
          <label>Eu sou</label>
          <div className="role-toggle">
            <button
              type="button"
              className={form.role === 'candidate' ? 'role-btn active' : 'role-btn'}
              onClick={() => setField('role', 'candidate')}
            >
              Candidato
            </button>
            <button
              type="button"
              className={form.role === 'recruiter' ? 'role-btn active' : 'role-btn'}
              onClick={() => setField('role', 'recruiter')}
            >
              Recrutador
            </button>
          </div>

          <label>Nome completo *</label>
          <input
            type="text"
            placeholder="Seu nome"
            value={form.name}
            onChange={e => setField('name', e.target.value)}
            required
          />

          <label>Email *</label>
          <input
            type="email"
            placeholder="seu@email.com"
            value={form.email}
            onChange={e => setField('email', e.target.value)}
            required
          />

          <label>Login *</label>
          <input
            type="text"
            placeholder="Como você quer entrar"
            value={form.login}
            onChange={e => setField('login', e.target.value)}
            required
          />

          <label>Senha *</label>
          <input
            type="password"
            placeholder="Mínimo 6 caracteres"
            value={form.password}
            onChange={e => setField('password', e.target.value)}
            required
          />

          {form.role === 'candidate' ? (
            <>
              <label>LinkedIn (URL)</label>
              <input
                type="url"
                placeholder="https://linkedin.com/in/seu-perfil"
                value={form.linkedin_url}
                onChange={e => setField('linkedin_url', e.target.value)}
              />

              <label>GitHub (URL)</label>
              <input
                type="url"
                placeholder="https://github.com/seu-usuario"
                value={form.github_url}
                onChange={e => setField('github_url', e.target.value)}
              />
            </>
          ) : (
            <>
              <label>Nome da empresa</label>
              <input
                type="text"
                placeholder="Como sua empresa se chama"
                value={form.company_name}
                onChange={e => setField('company_name', e.target.value)}
              />

              <label>CNPJ *</label>
              <input
                type="text"
                placeholder="00.000.000/0001-00"
                value={form.cnpj}
                onChange={e => setField('cnpj', e.target.value)}
                required={form.role === 'recruiter'}
              />

              <label>Departamento</label>
              <input
                type="text"
                placeholder="Ex: People & Culture"
                value={form.department}
                onChange={e => setField('department', e.target.value)}
              />

              <label>Cargo</label>
              <input
                type="text"
                placeholder="Ex: Tech Recruiter"
                value={form.position}
                onChange={e => setField('position', e.target.value)}
              />
            </>
          )}

          <button className="primary" type="submit" disabled={loading}>
            {loading ? 'Criando conta...' : 'Criar conta'}
          </button>

          {error && <div className="error">{error}</div>}
          {success && <div className="success">Conta criada com sucesso! Redirecionando para o login...</div>}

          <p className="signup">Já possui conta? <Link to="/">Entrar</Link></p>
        </form>
      </div>
    </div>
  )
}
