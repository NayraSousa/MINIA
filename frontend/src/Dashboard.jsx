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
  const [candidate, setCandidate] = useState(null)
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
      // evitar usar candidate de outro usuário
      const storedLocal = JSON.parse(localStorage.getItem('candidate') || 'null')
      if(storedLocal && storedLocal.user_id && storedLocal.user_id !== user.id){
        localStorage.removeItem('candidate')
        setCandidate(null)
      } else if(storedLocal){
        setCandidate(storedLocal)
      }
      ;(async function loadCandidate(){
        try{
          const endpoint = user.role === 'recruiter' ? `http://localhost:3333/recruiter/user/${user.id}` : `http://localhost:3333/candidate/user/${user.id}`
          const res = await fetch(endpoint, {
            headers: { Authorization: `Bearer ${token}` }
          })
          const data = await res.json().catch(() => ({}))
          if(res.ok){
            const profile = data.candidate || data.recruiter || null
            if(profile){
              setCandidate(profile)
              localStorage.setItem('candidate', JSON.stringify(profile))
            }
          }
        }catch(err){
          // ignore, keep possible local mock
        }
      })()
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
    localStorage.removeItem('candidate')
    setCandidate(null)
    navigate('/')
  }

  // CV modal actions
  // salva currículo em localStorage (mock) em vez de chamar backend
  async function saveCv(){
    setActionMessage(null)
    const token = localStorage.getItem('token')
    const user = JSON.parse(localStorage.getItem('user') || 'null')
    if(!user || !user.id){
      setActionMessage('Usuário não encontrado')
      return
    }
    // Tentar criar/atualizar candidate no backend para garantir candidate_id válido
    try{
      // verificar se já existe profile (candidate ou recruiter) para o user
      const isRecruiter = user.role === 'recruiter'
      const getEndpoint = isRecruiter ? `http://localhost:3333/recruiter/user/${user.id}` : `http://localhost:3333/candidate/user/${user.id}`
      const getRes = await fetch(getEndpoint, { headers: { Authorization: `Bearer ${token}` } })
      const getData = await getRes.json().catch(() => ({}))
      const body = { user_id: user.id, linkedin_url: '', github_url: '' }

      if(getRes.ok){
        const existing = getData.candidate || getData.recruiter || null
        if(existing && existing.id){
          // atualizar
          const updEndpoint = isRecruiter ? `http://localhost:3333/recruiter/${existing.id}` : `http://localhost:3333/candidate/${existing.id}`
          const upd = await fetch(updEndpoint, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify(body)
          })
          const updData = await upd.json().catch(() => ({}))
          if(upd.ok){
            const saved = updData.candidate || updData.recruiter || existing
            setCandidate(saved)
            localStorage.setItem('candidate', JSON.stringify(saved))
            setActionMessage(isRecruiter ? 'Perfil de recrutador atualizado' : 'Perfil de candidato atualizado')
            setShowCvModal(false)
            return
          }
        } else {
          // criar
          const createEndpoint = isRecruiter ? 'http://localhost:3333/recruiter' : 'http://localhost:3333/candidate'
          const create = await fetch(createEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
            body: JSON.stringify(body)
          })
          const createData = await create.json().catch(() => ({}))
          if(create.ok && (createData.candidate || createData.recruiter || createData.id)){
            const saved = createData.candidate || createData.recruiter || createData
            setCandidate(saved)
            localStorage.setItem('candidate', JSON.stringify(saved))
            setActionMessage(isRecruiter ? 'Perfil de recrutador criado' : 'Perfil de candidato criado')
            setShowCvModal(false)
            return
          }
        }
      }

      setActionMessage('Falha ao salvar no servidor — verifique a conexão')
    }catch(err){
      setActionMessage('Erro ao comunicar com o servidor')
    }
  }

  // Apply modal actions
  async function applyToJob(){
    setActionMessage(null)
    const token = localStorage.getItem('token')
    if(!selectedJob) return

    // tenta enviar para backend, se falhar cria mock local
    try{
      const storedCandidate = candidate || JSON.parse(localStorage.getItem('candidate') || 'null')
      if(!storedCandidate || !storedCandidate.id){
        setActionMessage('Salve seu currículo antes de candidatar')
        return
      }
      const candidate_id = storedCandidate.id
      const curriculum = resume

      // candidate_id must be a server UUID; block local/mock ids
      if(typeof candidate_id === 'string' && (candidate_id.startsWith('local-') || candidate_id.startsWith('mock-'))){
        setActionMessage('Salve seu currículo no servidor para criar seu perfil de candidato antes de candidatar')
        return
      }

      const res = await fetch('http://localhost:3333/job_application', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ job_id: selectedJob.id, candidate_id, curriculum })
      })

      if(res.ok){
        setActionMessage('Candidatura enviada com sucesso')
        setShowApplyModal(false)
        return
      }

      // Se 403 por role, tenta atualizar role do usuário para 'candidate' e tentar novamente
      if(res.status === 403){
        const body = await res.json().catch(() => ({}))
          if(body.error && body.error.toLowerCase().includes('role')){
            const user = JSON.parse(localStorage.getItem('user') || 'null')
            if(user && user.id){
              // tenta atualizar role via PUT /user/:id
              try{
                const upd = await fetch(`http://localhost:3333/user/${user.id}`, {
                  method: 'PUT',
                  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                  body: JSON.stringify({ role: 'candidate' })
                })
                if(upd.ok){
                  // atualizar localStorage
                  const updatedUser = { ...user, role: 'candidate' }
                  localStorage.setItem('user', JSON.stringify(updatedUser))
                  // tentar buscar profile (candidate ou recruiter) do backend
                  try{
                    const profileEndpoint = updatedUser.role === 'recruiter' ? `http://localhost:3333/recruiter/user/${user.id}` : `http://localhost:3333/candidate/user/${user.id}`
                    const resC = await fetch(profileEndpoint, { headers: { Authorization: `Bearer ${token}` } })
                    const dataC = await resC.json().catch(() => ({}))
                    const profile = dataC.candidate || dataC.recruiter || null
                    if(resC.ok && profile && profile.id){
                      setCandidate(profile)
                      localStorage.setItem('candidate', JSON.stringify(profile))
                      if(updatedUser.role === 'recruiter'){
                        setActionMessage('Usuário é recrutador; não é permitido candidatar')
                        return
                      }
                      const retry = await fetch('http://localhost:3333/job_application', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                        body: JSON.stringify({ job_id: selectedJob.id, candidate_id: profile.id, curriculum: resume })
                      })
                      if(retry.ok){
                        setActionMessage('Candidatura enviada com sucesso')
                        setShowApplyModal(false)
                        return
                      }
                    } else {
                      setActionMessage('Atualize seu currículo antes de candidatar')
                      return
                    }
                  }catch(err){
                    setActionMessage('Falha ao buscar perfil após atualizar role')
                    return
                  }
                } else {
                  const err = await upd.json().catch(() => ({}))
                  setActionMessage(err.error || 'Falha ao atualizar role do usuário')
                  return
                }
              }catch(err){
                setActionMessage('Falha ao atualizar role do usuário')
                return
              }
            }
          }
      }
    }catch(err){}

    // fallback mock
    try{
      const candidate = JSON.parse(localStorage.getItem('candidate') || 'null')
      const user = JSON.parse(localStorage.getItem('user') || 'null')
      const candidate_id = candidate?.id || `mock-${user?.id || 'unknown'}`
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
