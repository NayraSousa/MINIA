import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './dashboard.css'

export default function Dashboard(){
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [showCvModal, setShowCvModal] = useState(false)
  const [showApplyModal, setShowApplyModal] = useState(false)
  const [selectedJob, setSelectedJob] = useState(null)
  const [resume, setResume] = useState('')
  const [skills, setSkills] = useState('')
  const [actionMessage, setActionMessage] = useState(null)
  const navigate = useNavigate()

  const mockJobs = [
    { id: 'job-1', name: 'Desenvolvedor Backend', description: 'Node.js • APIs • Banco de dados' },
    { id: 'job-2', name: 'Analista de Dados', description: 'Python • SQL • Visualização' },
    { id: 'job-3', name: 'Estágio em TI', description: 'Lógica • Programação • Aprendizado' }
  ]

  useEffect(() => {
    const token = localStorage.getItem('token')
    if(!token){
      navigate('/')
      return
    }

    // carregar perfil do usuário para preencher currículo
    const user = JSON.parse(localStorage.getItem('user') || 'null')
    if(user){
      // se já tiver campos de resume/skills no objeto user, use-os
      if(user.resume) setResume(user.resume)
      if(user.skills) setSkills(user.skills)
    }

    async function loadJobs(){
      try{
        const res = await fetch('http://localhost:3333/job', {
          headers: { Authorization: `Bearer ${token}` }
        })
        const data = await res.json()
        if(!res.ok){
          setError(data.error || 'Erro ao buscar vagas')
          setLoading(false)
          return
        }
        setJobs(data.jobs || [])
      }catch(err){
        // fallback para dados mock quando backend não responde
        setJobs(mockJobs)
      }finally{
        setLoading(false)
      }
    }

    loadJobs()
  }, [navigate])

  function handleLogout(){
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/')
  }

  // CV modal actions
  // salva currículo em localStorage (mock) em vez de chamar backend
  async function saveCv(){
    setActionMessage(null)
    const user = JSON.parse(localStorage.getItem('user') || 'null')
    if(!user || !user.id){
      setActionMessage('Usuário não encontrado')
      return
    }

    try{
      const candidate = { id: user.id, user_id: user.id, curriculum: resume, skills }
      localStorage.setItem('candidate', JSON.stringify(candidate))
      setActionMessage('Currículo salvo (mock)')
      setShowCvModal(false)
    }catch(err){
      setActionMessage('Falha ao salvar localmente')
    }
  }

  // Apply modal actions
  async function applyToJob(){
    setActionMessage(null)
    const token = localStorage.getItem('token')
    if(!selectedJob) return

    // tenta enviar para backend, se falhar cria mock local
    try{
      const res = await fetch('http://localhost:3333/job_application', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ job_id: selectedJob.id })
      })

      if(res.ok){
        setActionMessage('Candidatura enviada com sucesso')
        setShowApplyModal(false)
        return
      }
    }catch(err){}

    // fallback mock
    try{
      const candidate = JSON.parse(localStorage.getItem('candidate') || 'null')
      const user = JSON.parse(localStorage.getItem('user') || 'null')
      const candidate_id = candidate?.id || user?.id || 'mock-candidate'
      const apps = JSON.parse(localStorage.getItem('mockApplications') || '[]')
      const newApp = { id: `app-${Date.now()}`, candidate_id, job_id: selectedJob.id, status: 'Inscrito', ai_score: '99.9', created_at: new Date().toISOString() }
      apps.push(newApp)
      localStorage.setItem('mockApplications', JSON.stringify(apps))
      setActionMessage('Candidatura criada (mock)')
      setShowApplyModal(false)
    }catch(err){
      setActionMessage('Falha ao criar candidatura mock')
    }
  }

  return (
    <div className="dashboard-root">
      <header className="dash-header">
        <h1>Vagas disponíveis</h1>
        <div>
          <button onClick={() => setShowCvModal(true)} className="save-cv">Meu currículo</button>
          <button onClick={handleLogout} className="logout">Sair</button>
        </div>
      </header>

      {actionMessage && <div className="action-message">{actionMessage}</div>}

      {loading && <p>Carregando vagas...</p>}
      {error && <p className="error">{error}</p>}

      <div className="jobs-list two-column">
        <div className="cv-panel">
          <h2>Meu currículo</h2>
          <label>Resumo profissional</label>
          <textarea placeholder="Descreva suas experiências, habilidades e objetivos profissionais..." value={resume} onChange={(e) => setResume(e.target.value)} />
          <label>Habilidades principais</label>
          <input placeholder="Ex: Python, Node.js, SQL" value={skills} onChange={e => setSkills(e.target.value)} />
          <div style={{marginTop:12}}>
            <button className="primary" onClick={saveCv}>Salvar currículo</button>
          </div>
        </div>

        <div className="jobs-panel">
          <h2>Vagas disponíveis</h2>
          {jobs.length === 0 && !loading && <p>Nenhuma vaga encontrada.</p>}
          {jobs.map((j) => (
            <div key={j.id} className="job-row">
              <div>
                <strong>{j.name}</strong>
                <div className="meta">{j.description}</div>
              </div>
              <div>
                <button className="apply" onClick={() => { setSelectedJob(j); setShowApplyModal(true); }}>Candidatar</button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {showCvModal && (
        <div className="modal-backdrop" onClick={() => setShowCvModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Meu currículo</h3>
            <label>Resumo profissional</label>
            <textarea value={resume} onChange={e => setResume(e.target.value)} />
            <label>Habilidades principais</label>
            <input value={skills} onChange={e => setSkills(e.target.value)} />
            <div className="modal-actions">
              <button onClick={() => setShowCvModal(false)}>Fechar</button>
              <button className="primary" onClick={saveCv}>Salvar currículo</button>
            </div>
          </div>
        </div>
      )}

      {showApplyModal && selectedJob && (
        <div className="modal-backdrop" onClick={() => setShowApplyModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Candidatar-se: {selectedJob.name}</h3>
            <p>{selectedJob.description}</p>
            <div className="modal-actions">
              <button onClick={() => setShowApplyModal(false)}>Cancelar</button>
              <button className="primary" onClick={applyToJob}>Candidatar</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
