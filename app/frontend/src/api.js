import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || '/api'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
})

export const getHealth = () => api.get('/health')

export const getStatistics = () => api.get('/api/statistics')

export const getAnalyses = (params) => api.get('/api/analyses', { params })

export const getAnalysis = (id) => api.get(`/api/analyses/${id}`)

export const getIOCs = (params) => api.get('/api/iocs', { params })

export const getAPTGroups = () => api.get('/api/apt-groups')

export const search = (query) => api.post('/api/search', query)

export default api
