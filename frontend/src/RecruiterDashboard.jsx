import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import './dashboard.css'
import apiClient from './services/apiClient'

export default function RecruiterDashboard(){
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [successMessage, setSuccessMessage] = useState(null)
  const [candidatesByJob, setCandidatesByJob] = useState({})
  const [loadingJobId, setLoadingJobId] = useState(null)
  const [recruiterId, setRecruiterId] = useState(null)
  const [needsProfile, setNeedsProfile] = useState(false)
  const [profileForm, setProfileForm] = useState({ company_name: '', cnpj: '', department: '', position: '' })
  const [completingProfile, setCompletingProfile] = useState(false)
  const [showJobModal, setShowJobModal] = useState(false)
  const [newJob, setNewJob] = useState({ name: '', description: '' })
  const [creating, setCreating] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    const token = localStorage.getItem('token')
    if(!token){
      navigate('/')
      return
    }

    const user = JSON.parse(localStorage.getItem('user') || 'null')
    if(!user || user.role !== 'recruiter'){
      navigate('/')
      return
    }

    const stored = JSON.parse(localStorage.getItem('recruiter') || 'null')
    if(stored && stored.user_id === user.id && stored.id){
      setRecruiterId(stored.id)
    }else{
      apiClient.get(`/recruiter/user/${user.id}`).then(({ ok, data, status }) => {
        if(status === 404){
          setLoading(false)
          setNeedsProfile(true)
          return
        }
        const profile = ok ? (data.recruiter || null) : null
        if(profile && profile.id){
          localStorage.setItem('recruiter', JSON.stringify(profile))
          setRecruiterId(profile.id)
        }else{
          setLoading(false)
          setError('Perfil de recrutador não encontrado')
        }
      }).catch(() => {
        setLoading(false)
        setError('Falha ao buscar perfil de recrutador')
      })
    }
  }, [navigate])

  async function completeProfile(){
    setError(null)
    if(!profileForm.cnpj.trim()){
      setError('Informe o CNPJ da empresa')
      return
    }
    setCompletingProfile(true)
    try{
      const { ok, data } = await apiClient.post('/recruiter/complete-profile', {
        company_name: profileForm.company_name.trim(),
        cnpj: profileForm.cnpj.replace(/\D/g, ''),
        department: profileForm.department.trim(),
        position: profileForm.position.trim()
      })
      if(!ok){
        setError(data?.error || 'Falha ao completar perfil')
        return
      }
      const recruiter = data.recruiter
      const user = JSON.parse(localStorage.getItem('user') || 'null')
      const enriched = { ...recruiter, user_id: user?.id }
      localStorage.setItem('recruiter', JSON.stringify(enriched))
      setRecruiterId(enriched.id)
      setNeedsProfile(false)
      setSuccessMessage('Perfil de recrutador criado com sucesso')
    }catch{
      setError('Falha ao comunicar com o servidor')
    }finally{
      setCompletingProfile(false)
    }
  }

  useEffect(() => {
    if(!recruiterId) return

    let cancelled = false
    setLoading(true)

    apiClient.get(`/job/recruiter/${recruiterId}`).then(({ ok, data }) => {
      if(cancelled) return
      if(!ok){
        setError(data?.error || 'Erro ao buscar vagas')
        setLoading(false)
        return
      }
      setJobs(data.jobs || [])
      setLoading(false)
    }).catch(() => {
      if(cancelled) return
      setError('Falha ao buscar vagas')
      setLoading(false)
    })

    return () => { cancelled = true }
  }, [recruiterId])

  function handleLogout(){
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    localStorage.removeItem('recruiter')
    navigate('/')
  }

  async function createJob(){
    setError(null)
    setSuccessMessage(null)
    if(!newJob.name.trim() || !newJob.description.trim()){
      setError('Informe nome e descrição da vaga')
      return
    }
    setCreating(true)
    try{
      const { ok, data } = await apiClient.post('/job', {
        name: newJob.name.trim(),
        description: newJob.description.trim(),
        userId: JSON.parse(localStorage.getItem('user')).id
      })
      if(!ok){
        setError(data?.error || 'Falha ao criar vaga')
        return
      }
      setSuccessMessage('Vaga criada com sucesso')
      setShowJobModal(false)
      setNewJob({ name: '', description: '' })
      if(data?.job){
        setJobs(prev => [...prev, data.job])
      }else{
        if(recruiterId) loadJobsForRecruiter(recruiterId)
      }
    }catch{
      setError('Falha ao comunicar com o servidor')
    }finally{
      setCreating(false)
    }
  }

  function loadJobsForRecruiter(rid){
    setLoading(true)
    apiClient.get(`/job/recruiter/${rid}`).then(({ ok, data }) => {
      if(!ok){
        setError(data?.error || 'Erro ao buscar vagas')
      }else{
        setJobs(data.jobs || [])
      }
      setLoading(false)
    }).catch(() => {
      setError('Falha ao buscar vagas')
      setLoading(false)
    })
  }

  async function loadCandidates(job){
    setError(null)
    setLoadingJobId(job.id)
    try{
      const { ok, data } = await apiClient.get(`/job_application/job/${job.id}`)
      if(!ok){
        setError(data?.error || 'Erro ao buscar candidaturas')
        return
      }
      setCandidatesByJob(prev => ({ ...prev, [job.id]: data.jobApplications || [] }))
    }catch{
      setError('Falha ao buscar candidaturas')
    }finally{
      setLoadingJobId(null)
    }
  }

  return (
    <div className="dashboard-root">
      <header className="dash-header">
        <h1>Painel do recrutador</h1>
        <div>
          <button onClick={() => setShowJobModal(true)} className="save-cv">Nova vaga</button>
          <button onClick={handleLogout} className="logout">Sair</button>
        </div>
      </header>

      {error && <div className="error">{error}</div>}
      {successMessage && <div className="action-message">{successMessage}</div>}

      {needsProfile && !loading && (
        <div className="recruiter-job-card">
          <h3>Complete seu perfil de recrutador</h3>
          <p className="meta">
            Detectamos que sua conta de recrutador ainda não tem um perfil ativo. Preencha os dados da empresa para continuar.
          </p>
          <label>Nome da empresa</label>
          <input
            value={profileForm.company_name}
            onChange={(e) => setProfileForm(prev => ({ ...prev, company_name: e.target.value }))}
            placeholder="Como sua empresa se chama"
            disabled={completingProfile}
          />
          <label>CNPJ *</label>
          <input
            value={profileForm.cnpj}
            onChange={(e) => setProfileForm(prev => ({ ...prev, cnpj: e.target.value }))}
            placeholder="00.000.000/0001-00"
            disabled={completingProfile}
          />
          <label>Departamento</label>
          <input
            value={profileForm.department}
            onChange={(e) => setProfileForm(prev => ({ ...prev, department: e.target.value }))}
            placeholder="Ex: People & Culture"
            disabled={completingProfile}
          />
          <label>Cargo</label>
          <input
            value={profileForm.position}
            onChange={(e) => setProfileForm(prev => ({ ...prev, position: e.target.value }))}
            placeholder="Ex: Tech Recruiter"
            disabled={completingProfile}
          />
          <div className="modal-actions">
            <button className="primary" onClick={completeProfile} disabled={completingProfile}>
              {completingProfile ? 'Salvando...' : 'Concluir cadastro'}
            </button>
          </div>
        </div>
      )}

      {loading && <p>Carregando vagas...</p>}

      {!loading && jobs.length === 0 && (
        <p>Nenhuma vaga associada a este recrutador.</p>
      )}

      <div className="recruiter-jobs">
        {jobs.map(job => {
          const ranked = candidatesByJob[job.id] || []
          return (
            <div key={job.id} className="recruiter-job-card">
              <div className="recruiter-job-head">
                <div>
                  <h3>{job.name}</h3>
                  <div className="meta">{job.description}</div>
                </div>
                <button
                  className="primary"
                  onClick={() => loadCandidates(job)}
                  disabled={loadingJobId === job.id}
                >
                  {loadingJobId === job.id
                    ? 'Carregando...'
                    : ranked.length > 0
                      ? 'Atualizar candidatos'
                      : 'Ver candidatos'}
                </button>
              </div>

              {ranked.length > 0 && (
                <div className="ranked-list">
                  <h4>Candidatos ranqueados por compatibilidade</h4>
                  {ranked.map((r, idx) => (
                    <div key={r.id} className="ranked-row">
                      <span className="rank-pos">#{idx + 1}</span>
                      <span className="rank-candidate">
                        <strong>{r.candidate_name || 'Candidato'}</strong>
                        {r.candidate_email && <div className="meta">{r.candidate_email}</div>}
                      </span>
                      <span className="rank-score">
                        {r.ai_score != null ? `${r.ai_score}` : '—'}
                      </span>
                      <span className="rank-status">{r.compatibility || '—'}</span>
                    </div>
                  ))}
                </div>
              )}

              {loadingJobId !== job.id && ranked.length === 0 && (
                <p className="meta">Clique em "Ver candidatos" para carregar a lista ranqueada.</p>
              )}
            </div>
          )
        })}
      </div>

      {showJobModal && (
        <div className="modal-backdrop" onClick={() => !creating && setShowJobModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Nova vaga</h3>
            <label>Nome da vaga</label>
            <input
              value={newJob.name}
              onChange={(e) => setNewJob(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Ex: Desenvolvedor Backend"
              disabled={creating}
            />
            <label>Descrição</label>
            <textarea
              value={newJob.description}
              onChange={(e) => setNewJob(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Descreva responsabilidades, requisitos e benefícios..."
              disabled={creating}
            />
            <div className="modal-actions">
              <button onClick={() => setShowJobModal(false)} disabled={creating}>Cancelar</button>
              <button className="primary" onClick={createJob} disabled={creating}>
                {creating ? 'Criando...' : 'Criar vaga'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
