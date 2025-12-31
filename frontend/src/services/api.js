import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080'

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const getRules = async (collection = null) => {
  const params = collection ? { collection } : {}
  const response = await api.get('/api/rules', { params })
  return response.data
}

export const getRule = async (id) => {
  const response = await api.get(`/api/rules/${id}`)
  return response.data
}

export const createRule = async (ruleData) => {
  const response = await api.post('/api/rules', ruleData)
  return response.data
}

export const updateRule = async (id, ruleData) => {
  const response = await api.put(`/api/rules/${id}`, ruleData)
  return response.data
}

export const deleteRule = async (id) => {
  await api.delete(`/api/rules/${id}`)
}

export const exportXML = async (rules) => {
  const response = await api.post(
    '/api/export/xml',
    {
      rules,
      enforcement_mode: 'AuditOnly',
      version: '1',
    },
    {
      responseType: 'text',
    }
  )
  return response.data
}

export const exportCollectionXML = async (collectionType) => {
  const response = await api.post(
    `/api/export/collection/${collectionType}`,
    {},
    {
      responseType: 'text',
    }
  )
  return response.data
}

export const importXML = async (xmlContent) => {
  const response = await api.post('/api/import/xml', xmlContent, {
    headers: {
      'Content-Type': 'text/plain',
    },
  })
  return response.data
}

export const getCollections = async () => {
  const response = await api.get('/api/collections')
  return response.data
}

export const getDefaultRules = async () => {
  const response = await api.get('/api/default-rules')
  return response.data
}

export const importDefaultRules = async (collectionType = null) => {
  const params = collectionType ? { collection_type: collectionType } : {}
  const response = await api.post('/api/import/default-rules', null, { params })
  return response.data
}

export const deleteAllRules = async (collectionType = null) => {
  const params = collectionType ? { collection: collectionType } : {}
  await api.delete('/api/rules', { params })
}

