const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3333'

function getToken(){
  return localStorage.getItem('token')
}

async function request(path, options = {}){
  const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {})
  const token = getToken()
  if(token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(`${BASE_URL}${path}`, Object.assign({}, options, { headers }))
  let data = null
  try{ data = await res.json() }catch(e){}
  return { ok: res.ok, status: res.status, data, res }
}

export default {
  get: (path) => request(path, { method: 'GET' }),
  post: (path, body) => request(path, { method: 'POST', body: JSON.stringify(body) }),
  put: (path, body) => request(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: (path) => request(path, { method: 'DELETE' }),
  rawRequest: request
}
