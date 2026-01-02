import React, { useState, useEffect } from 'react'
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Box,
  Typography,
  Chip,
  IconButton,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  Tooltip,
  CircularProgress,
} from '@mui/material'
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Info as InfoIcon,
  Visibility as VisibilityIcon,
  Edit as EditIcon,
  FileUpload as FileUploadIcon,
} from '@mui/icons-material'
import { createRule, updateRule, getCollections } from '../services/api'
import { calculateFileHash } from '../utils/fileUtils'

// Helper function to suggest environment variable for hardcoded paths
const suggestEnvironmentVariable = (path) => {
  if (!path || path.includes('%')) return null // Already using env var or empty
  
  const pathMappings = [
    { 
      regex: /^([A-Z]:)\\(Windows\\)?System32(.*)/i, 
      env: '%SYSTEM32%',
      replacement: (match, drive, win, rest) => {
        const cleanRest = rest ? rest.replace(/^\\/, '') : '*'
        return `%SYSTEM32%\\${cleanRest}`
      }
    },
    { 
      regex: /^([A-Z]:)\\Windows(?!\\System32)(.*)/i, 
      env: '%WINDIR%',
      replacement: (match, drive, rest) => {
        const cleanRest = rest ? rest.replace(/^\\/, '') : '*'
        return `%WINDIR%\\${cleanRest}`
      }
    },
    { 
      regex: /^([A-Z]:)\\Program Files \(x86\)(.*)/i, 
      env: '%PROGRAMFILES(X86)%',
      replacement: (match, drive, rest) => {
        const cleanRest = rest ? rest.replace(/^\\/, '') : '*'
        return `%PROGRAMFILES(X86)%\\${cleanRest}`
      }
    },
    { 
      regex: /^([A-Z]:)\\Program Files(?! \(x86\))(.*)/i, 
      env: '%PROGRAMFILES%',
      replacement: (match, drive, rest) => {
        const cleanRest = rest ? rest.replace(/^\\/, '') : '*'
        return `%PROGRAMFILES%\\${cleanRest}`
      }
    },
    { 
      regex: /^([A-Z]:)\\ProgramData(.*)/i, 
      env: '%PROGRAMDATA%',
      replacement: (match, drive, rest) => {
        const cleanRest = rest ? rest.replace(/^\\/, '') : '*'
        return `%PROGRAMDATA%\\${cleanRest}`
      }
    },
  ]
  
  try {
    for (const mapping of pathMappings) {
      const match = path.match(mapping.regex)
      if (match) {
        const suggested = mapping.replacement(...match)
        // Clean up double backslashes and trailing backslash before wildcard
        const cleaned = suggested.replace(/\\\\+/g, '\\').replace(/\\\*$/g, '\\*')
        return cleaned
      }
    }
  } catch (error) {
    console.error('Error in suggestEnvironmentVariable:', error)
    return null
  }
  
  return null
}

const RuleForm = ({ open, onClose, rule, onSave }) => {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    collection: 'Exe',
    action: 'Allow',
    user_or_group_sid: '',
    conditions: [],
    exceptions: [],
  })
  const [collections, setCollections] = useState([])
  const [newCondition, setNewCondition] = useState({
    type: 'FilePathCondition',
    path: '',
    publisher_name: '',
    product_name: '',
    binary_name: '',
    version_range_type: 'any',
    version_value: '',
    version: '',
    file_hash: '',
    source_file_name: '',
  })
  const [newException, setNewException] = useState({
    type: 'FilePathCondition',
    path: '',
    publisher_name: '',
    product_name: '',
    binary_name: '',
    version_range_type: 'any',
    version_value: '',
    version: '',
    file_hash: '',
    hash_type: 'SHA256',
    source_file_name: '',
    source_file_length: '',
  })
  const [pathSuggestion, setPathSuggestion] = useState({ original: '', suggested: '', type: null }) // type: 'condition' or 'exception'
  const [exceptionDetailDialog, setExceptionDetailDialog] = useState({ open: false, exception: null, index: null })
  const [editingExceptionIndex, setEditingExceptionIndex] = useState(null) // null when not editing, index when editing
  const [loadingHash, setLoadingHash] = useState(false)
  const [hashFileInputKey, setHashFileInputKey] = useState(0) // For resetting file input

  useEffect(() => {
    loadCollections()
  }, [])

  useEffect(() => {
    if (rule) {
      setFormData({
        name: rule.name || '',
        description: rule.description || '',
        collection: rule.collection || 'Exe',
        action: rule.action || 'Allow',
        user_or_group_sid: rule.user_or_group_sid || '',
        conditions: rule.conditions || [],
        exceptions: rule.exceptions || [],
      })
    } else {
      setFormData({
        name: '',
        description: '',
        collection: 'Exe',
        action: 'Allow',
        user_or_group_sid: '',
        conditions: [],
        exceptions: [],
      })
    }
  }, [rule, open])

  const loadCollections = async () => {
    try {
      const data = await getCollections()
      setCollections(data.collections || [])
    } catch (error) {
      console.error('Failed to load collections:', error)
    }
  }

  const handleChange = (field) => (event) => {
    setFormData({
      ...formData,
      [field]: event.target.value,
    })
  }

  const handleConditionTypeChange = (event) => {
    setNewCondition({
      ...newCondition,
      type: event.target.value,
    })
  }

  const handleConditionFieldChange = (field) => (event) => {
    const value = event.target.value
    setNewCondition({
      ...newCondition,
      [field]: value,
    })
    
    // Check for path suggestions when path field changes
    if (field === 'path' && value) {
      const suggested = suggestEnvironmentVariable(value)
      if (suggested && suggested !== value) {
        setPathSuggestion({ original: value, suggested, type: 'condition' })
      } else {
        setPathSuggestion({ original: '', suggested: '', type: null })
      }
    }
  }

  const handleAcceptSuggestion = () => {
    if (pathSuggestion.type === 'condition') {
      setNewCondition({
        ...newCondition,
        path: pathSuggestion.suggested,
      })
    } else if (pathSuggestion.type === 'exception') {
      setNewException({
        ...newException,
        path: pathSuggestion.suggested,
      })
    }
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleDismissSuggestion = () => {
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleAddCondition = () => {
    const condition = { ...newCondition }
    let newConditionObj = null
    
    // Format condition based on type
    if (condition.type === 'FilePathCondition') {
      if (!condition.path) {
        alert('Please enter a path')
        return
      }
      newConditionObj = {
        type: 'FilePathCondition',
        path: condition.path,
      }
    } else if (condition.type === 'FilePublisherCondition') {
      if (!condition.publisher_name) {
        alert('Please enter a publisher name')
        return
      }
      // Build version based on version_range_type
      let version = '*'
      if (condition.version_range_type === 'and_above' && condition.version_value) {
        version = `${condition.version_value}-*`
      } else if (condition.version_range_type === 'and_below' && condition.version_value) {
        version = `*-${condition.version_value}`
      } else if (condition.version_range_type === 'exactly' && condition.version_value) {
        version = condition.version_value
      }
      
      newConditionObj = {
        type: 'FilePublisherCondition',
        publisher_name: condition.publisher_name,
        product_name: condition.product_name || null,
        binary_name: condition.binary_name || null,
        version: version,
        version_range_type: condition.version_range_type || 'any',
        version_value: condition.version_value || '',
      }
    } else if (condition.type === 'FileHashCondition') {
      if (!condition.file_hash || !condition.source_file_name) {
        alert('Please enter file hash and source file name')
        return
      }
      // Create a separate FileHashCondition for each hash
      newConditionObj = {
        type: 'FileHashCondition',
        file_hash: condition.file_hash,
        hash_type: 'SHA256',
        source_file_name: condition.source_file_name,
      }
    }

    if (newConditionObj) {
      setFormData({
        ...formData,
        conditions: [...formData.conditions, newConditionObj],
      })
    }
    setNewCondition({
      type: 'FilePathCondition',
      path: '',
      publisher_name: '',
      product_name: '',
      binary_name: '',
      version_range_type: 'any',
      version_value: '',
      version: '',
      file_hash: '',
      source_file_name: '',
    })
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleRemoveCondition = (index) => {
    setFormData({
      ...formData,
      conditions: formData.conditions.filter((_, i) => i !== index),
    })
  }

  const handleExceptionFieldChange = (field) => (event) => {
    try {
      const value = event.target.value
      setNewException({
        ...newException,
        [field]: value,
      })
      
      // Check for path suggestions when path field changes
      if (field === 'path' && value) {
        try {
          const suggested = suggestEnvironmentVariable(value)
          if (suggested && suggested !== value) {
            setPathSuggestion({ original: value, suggested, type: 'exception' })
          } else {
            setPathSuggestion({ original: '', suggested: '', type: null })
          }
        } catch (error) {
          console.error('Error checking path suggestion:', error)
          setPathSuggestion({ original: '', suggested: '', type: null })
        }
      } else if (field === 'path' && !value) {
        setPathSuggestion({ original: '', suggested: '', type: null })
      }
    } catch (error) {
      console.error('Error in handleExceptionFieldChange:', error)
    }
  }

  const handleEditException = (index) => {
    const exception = formData.exceptions[index]
    setEditingExceptionIndex(index)
    
    // Populate form with existing exception data
    if (exception.type === 'FilePathCondition') {
      setNewException({
        type: 'FilePathCondition',
        path: exception.path || '',
        publisher_name: '',
        product_name: '',
        binary_name: '',
        version_range_type: 'any',
        version_value: '',
        version: '',
        file_hash: '',
        hash_type: 'SHA256',
        source_file_name: '',
        source_file_length: '',
      })
    } else if (exception.type === 'FilePublisherCondition') {
      setNewException({
        type: 'FilePublisherCondition',
        path: '',
        publisher_name: exception.publisher_name || '',
        product_name: exception.product_name || '',
        binary_name: exception.binary_name || '',
        version_range_type: exception.version_range_type || 'any',
        version_value: exception.version_value || '',
        version: exception.version || '',
        file_hash: '',
        hash_type: 'SHA256',
        source_file_name: '',
        source_file_length: '',
      })
    } else if (exception.type === 'FileHashCondition') {
      setNewException({
        type: 'FileHashCondition',
        path: '',
        publisher_name: '',
        product_name: '',
        binary_name: '',
        version_range_type: 'any',
        version_value: '',
        version: '',
        file_hash: exception.file_hash || '',
        hash_type: exception.hash_type || 'SHA256',
        source_file_name: exception.source_file_name || '',
        source_file_length: exception.source_file_length || '',
      })
    }
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleCancelEditException = () => {
    setEditingExceptionIndex(null)
    setNewException({
      type: 'FilePathCondition',
      path: '',
      publisher_name: '',
      product_name: '',
      binary_name: '',
      version_range_type: 'any',
      version_value: '',
      version: '',
      file_hash: '',
      hash_type: 'SHA256',
      source_file_name: '',
      source_file_length: '',
    })
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleAddException = () => {
    let exceptionObj = {}
    
    if (newException.type === 'FilePathCondition') {
      if (!newException.path) {
        alert('Please enter a path')
        return
      }
      exceptionObj = {
        type: 'FilePathCondition',
        path: newException.path,
      }
    } else if (newException.type === 'FilePublisherCondition') {
      if (!newException.publisher_name) {
        alert('Please enter a publisher name')
        return
      }
      // Build version based on version_range_type
      let version = '*'
      if (newException.version_range_type === 'and_above' && newException.version_value) {
        version = `${newException.version_value}-*`
      } else if (newException.version_range_type === 'and_below' && newException.version_value) {
        version = `*-${newException.version_value}`
      } else if (newException.version_range_type === 'exactly' && newException.version_value) {
        version = newException.version_value
      }
      
      exceptionObj = {
        type: 'FilePublisherCondition',
        publisher_name: newException.publisher_name || '*',
        product_name: newException.product_name || '*',
        binary_name: newException.binary_name || '*',
        version: version,
        version_range_type: newException.version_range_type || 'any',
        version_value: newException.version_value || '',
      }
    } else if (newException.type === 'FileHashCondition') {
      if (!newException.file_hash) {
        alert('Please enter a file hash')
        return
      }
      exceptionObj = {
        type: 'FileHashCondition',
        file_hash: newException.file_hash,
        hash_type: newException.hash_type || 'SHA256',
        source_file_name: newException.source_file_name || '',
        source_file_length: newException.source_file_length || null,
      }
    }
    
    if (editingExceptionIndex !== null) {
      // Update existing exception
      const updatedExceptions = [...formData.exceptions]
      updatedExceptions[editingExceptionIndex] = exceptionObj
      setFormData({
        ...formData,
        exceptions: updatedExceptions,
      })
      setEditingExceptionIndex(null)
    } else {
      // Add new exception
      setFormData({
        ...formData,
        exceptions: [...formData.exceptions, exceptionObj],
      })
    }
    
    setNewException({
      type: 'FilePathCondition',
      path: '',
      publisher_name: '',
      product_name: '',
      binary_name: '',
      version_range_type: 'any',
      version_value: '',
      version: '',
      file_hash: '',
      hash_type: 'SHA256',
      source_file_name: '',
      source_file_length: '',
    })
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleRemoveException = (index) => {
    setFormData({
      ...formData,
      exceptions: formData.exceptions.filter((_, i) => i !== index),
    })
    // If we're editing the exception that was deleted, cancel edit mode
    if (editingExceptionIndex === index) {
      handleCancelEditException()
    } else if (editingExceptionIndex !== null && editingExceptionIndex > index) {
      // If we're editing a later exception, adjust the index
      setEditingExceptionIndex(editingExceptionIndex - 1)
    }
  }

  const handleHashFileSelect = async (event, isException = false) => {
    const file = event.target.files[0]
    if (!file) return
    
    setLoadingHash(true)
    try {
      const hashInfo = await calculateFileHash(file)
      
      if (isException) {
        setNewException({
          ...newException,
          type: 'FileHashCondition',
          file_hash: hashInfo.hash,
          hash_type: 'SHA256',
          source_file_name: hashInfo.filename,
          source_file_length: hashInfo.size.toString(),
        })
      } else {
        setNewCondition({
          ...newCondition,
          type: 'FileHashCondition',
          file_hash: hashInfo.hash,
          hash_type: 'SHA256',
          source_file_name: hashInfo.filename,
          source_file_length: hashInfo.size.toString(),
        })
      }
      
      // Reset file input
      setHashFileInputKey(prev => prev + 1)
      event.target.value = ''
    } catch (error) {
      alert(`Failed to calculate file hash: ${error.message}`)
      console.error('Hash calculation error:', error)
    } finally {
      setLoadingHash(false)
    }
  }

  const handleSubmit = async () => {
    if (!formData.name) {
      alert('Please enter a rule name')
      return
    }

    if (formData.conditions.length === 0) {
      alert('Please add at least one condition')
      return
    }

    try {
      if (rule) {
        await updateRule(rule.id, formData)
      } else {
        await createRule(formData)
      }
      onSave()
      onClose()
    } catch (error) {
      console.error('Failed to save rule:', error)
      alert('Failed to save rule: ' + (error.response?.data?.detail || error.message))
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>{rule ? 'Edit Rule' : 'Create New Rule'}</DialogTitle>
      <DialogContent>
        <Box sx={{ pt: 2 }}>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Rule Name"
                value={formData.name}
                onChange={handleChange('name')}
                required
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                value={formData.description}
                onChange={handleChange('description')}
                multiline
                rows={2}
              />
            </Grid>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Collection Type</InputLabel>
                <Select
                  value={formData.collection}
                  onChange={handleChange('collection')}
                  label="Collection Type"
                >
                  {collections.map((col) => (
                    <MenuItem key={col.value} value={col.value}>
                      {col.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={6}>
              <FormControl fullWidth>
                <InputLabel>Action</InputLabel>
                <Select
                  value={formData.action}
                  onChange={handleChange('action')}
                  label="Action"
                >
                  <MenuItem value="Allow">Allow</MenuItem>
                  <MenuItem value="Deny">Deny</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="User or Group SID (optional, defaults to Everyone)"
                value={formData.user_or_group_sid}
                onChange={handleChange('user_or_group_sid')}
                placeholder="S-1-1-0"
                helperText="Leave empty for Everyone (S-1-1-0)"
              />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>
                Conditions
              </Typography>
              {formData.conditions.length === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  No conditions added yet.
                </Typography>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  {formData.conditions.map((condition, index) => {
                    if (condition.type === 'FilePathCondition') {
                      return (
                        <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="body2" fontWeight="medium">Path Condition</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                              {condition.path || 'N/A'}
                            </Typography>
                          </Box>
                          <IconButton size="small" onClick={() => handleRemoveCondition(index)} color="error">
                            <DeleteIcon />
                          </IconButton>
                        </Box>
                      )
                    } else if (condition.type === 'FilePublisherCondition') {
                      let versionInfo = 'Any Version'
                      if (condition.version_range_type === 'and_above' && condition.version_value) {
                        versionInfo = `Version ${condition.version_value} and above`
                      } else if (condition.version_range_type === 'and_below' && condition.version_value) {
                        versionInfo = `Version ${condition.version_value} and below`
                      } else if (condition.version_range_type === 'exactly' && condition.version_value) {
                        versionInfo = `Exactly version ${condition.version_value}`
                      } else if (condition.version && condition.version !== '*') {
                        versionInfo = `Version: ${condition.version}`
                      }
                      
                      return (
                        <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="body2" fontWeight="medium">Publisher Condition</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.875rem' }}>
                              {condition.publisher_name || 'N/A'}
                            </Typography>
                            {(condition.product_name || condition.binary_name) && (
                              <Typography variant="caption" color="text.secondary">
                                Product: {condition.product_name || '*'}, Binary: {condition.binary_name || '*'}
                              </Typography>
                            )}
                            <Typography variant="caption" color="text.secondary">
                              {versionInfo}
                            </Typography>
                          </Box>
                          <IconButton size="small" onClick={() => handleRemoveCondition(index)} color="error">
                            <DeleteIcon />
                          </IconButton>
                        </Box>
                      )
                    } else if (condition.type === 'FileHashCondition') {
                      const hashValue = condition.file_hash || ''
                      return (
                        <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="body2" fontWeight="medium">Hash Condition</Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ fontSize: '0.875rem' }}>
                              File: <strong>{condition.source_file_name || 'N/A'}</strong>
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                              Hash: {hashValue || 'N/A'}
                            </Typography>
                            {condition.source_file_length && (
                              <Typography variant="caption" color="text.secondary">
                                Size: {condition.source_file_length} bytes
                              </Typography>
                            )}
                          </Box>
                          <IconButton size="small" onClick={() => handleRemoveCondition(index)} color="error">
                            <DeleteIcon />
                          </IconButton>
                        </Box>
                      )
                    } else {
                      return (
                        <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1, p: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="body2">{condition.type || 'Unknown'}</Typography>
                          </Box>
                          <IconButton size="small" onClick={() => handleRemoveCondition(index)} color="error">
                            <DeleteIcon />
                          </IconButton>
                        </Box>
                      )
                    }
                  })}
                </Box>
              )}
            </Grid>

            <Grid item xs={12}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Add Condition</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <FormControl fullWidth>
                      <InputLabel>Condition Type</InputLabel>
                      <Select
                        value={newCondition.type}
                        onChange={handleConditionTypeChange}
                        label="Condition Type"
                      >
                        <MenuItem value="FilePathCondition">Path Condition</MenuItem>
                        <MenuItem value="FilePublisherCondition">Publisher Condition</MenuItem>
                        <MenuItem value="FileHashCondition">Hash Condition</MenuItem>
                      </Select>
                    </FormControl>

                    {newCondition.type === 'FilePathCondition' && (
                      <>
                        <TextField
                          fullWidth
                          label="Path"
                          value={newCondition.path}
                          onChange={handleConditionFieldChange('path')}
                          placeholder="C:\\Program Files\\* or %WINDIR%\\*"
                          helperText="Use wildcards (*) and environment variables"
                        />
                        {pathSuggestion.type === 'condition' && pathSuggestion.original === newCondition.path && (
                          <Alert 
                            severity="info" 
                            action={
                              <Box sx={{ display: 'flex', gap: 1 }}>
                                <Button size="small" onClick={handleAcceptSuggestion}>
                                  Use {pathSuggestion.suggested}
                                </Button>
                                <Button size="small" onClick={handleDismissSuggestion}>
                                  Keep original
                                </Button>
                              </Box>
                            }
                            sx={{ mt: 1 }}
                          >
                            <Typography variant="body2" sx={{ mb: 0.5 }}>
                              Trying to add: <code>{pathSuggestion.original}</code>
                            </Typography>
                            <Typography variant="body2">
                              Want to make it: <code style={{ fontWeight: 'bold' }}>{pathSuggestion.suggested}</code>?
                            </Typography>
                          </Alert>
                        )}
                      </>
                    )}

                    {newCondition.type === 'FilePublisherCondition' && (
                      <>
                        <TextField
                          fullWidth
                          label="Publisher Name"
                          value={newCondition.publisher_name}
                          onChange={handleConditionFieldChange('publisher_name')}
                          required
                          placeholder="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US"
                        />
                        <TextField
                          fullWidth
                          label="Product Name (optional)"
                          value={newCondition.product_name}
                          onChange={handleConditionFieldChange('product_name')}
                          placeholder="*"
                        />
                        <TextField
                          fullWidth
                          label="Binary Name (optional)"
                          value={newCondition.binary_name}
                          onChange={handleConditionFieldChange('binary_name')}
                          placeholder="*"
                        />
                        <FormControl fullWidth>
                          <InputLabel>Version Range Type</InputLabel>
                          <Select
                            value={newCondition.version_range_type}
                            onChange={(e) => setNewCondition({ ...newCondition, version_range_type: e.target.value })}
                            label="Version Range Type"
                          >
                            <MenuItem value="any">Any Version</MenuItem>
                            <MenuItem value="and_above">And Above</MenuItem>
                            <MenuItem value="and_below">And Below</MenuItem>
                            <MenuItem value="exactly">Exactly</MenuItem>
                          </Select>
                        </FormControl>
                        {newCondition.version_range_type !== 'any' && (
                          <TextField
                            fullWidth
                            label="Version"
                            value={newCondition.version_value}
                            onChange={handleConditionFieldChange('version_value')}
                            placeholder="10.840.20348.587"
                            helperText={
                              newCondition.version_range_type === 'and_above' ? 'Minimum version (and above)' :
                              newCondition.version_range_type === 'and_below' ? 'Maximum version (and below)' :
                              'Exact version'
                            }
                            required
                          />
                        )}
                      </>
                    )}

                    {newCondition.type === 'FileHashCondition' && (
                      <>
                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
                          <TextField
                            fullWidth
                            label="File Hash (SHA256)"
                            value={newCondition.file_hash}
                            onChange={handleConditionFieldChange('file_hash')}
                            required
                            placeholder="A1B2C3D4... or 0xA1B2C3D4..."
                            helperText="Enter SHA256 hash (with or without 0x prefix)"
                          />
                          <input
                            accept="*"
                            style={{ display: 'none' }}
                            id="hash-file-input-condition"
                            key={hashFileInputKey}
                            type="file"
                            onChange={(e) => handleHashFileSelect(e, false)}
                          />
                          <Button
                            variant="outlined"
                            component="label"
                            htmlFor="hash-file-input-condition"
                            startIcon={loadingHash ? <CircularProgress size={16} /> : <FileUploadIcon />}
                            disabled={loadingHash}
                            sx={{ mt: 1, whiteSpace: 'nowrap' }}
                            title="Select a file to calculate its SHA256 hash"
                          >
                            {loadingHash ? 'Calculating...' : 'From File'}
                          </Button>
                        </Box>
                        <TextField
                          fullWidth
                          label="Source File Name"
                          value={newCondition.source_file_name}
                          onChange={handleConditionFieldChange('source_file_name')}
                          required
                          placeholder="example.dll"
                        />
                      </>
                    )}

                    <Button
                      variant="outlined"
                      startIcon={<AddIcon />}
                      onClick={handleAddCondition}
                    >
                      Add Condition
                    </Button>
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>
                Exceptions {formData.exceptions.length > 0 && `(${formData.exceptions.length})`}
              </Typography>
              {formData.exceptions.length === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  No exceptions. Exceptions exclude paths, publishers, or hashes from the rule conditions.
                </Typography>
              ) : (
                formData.exceptions.map((exception, index) => {
                  let label = ''
                  if (exception.type === 'FilePathCondition') {
                    label = `Path: ${exception.path}`
                  } else if (exception.type === 'FilePublisherCondition') {
                    // Truncate publisher name if too long
                    const pubName = exception.publisher_name || ''
                    const displayName = pubName.length > 40 ? pubName.substring(0, 40) + '...' : pubName
                    label = `Publisher: ${displayName}`
                  } else if (exception.type === 'FileHashCondition') {
                    label = `Hash: ${exception.file_hash.substring(0, 16)}... (SHA256)`
                  } else {
                    label = `Exception ${index + 1}`
                  }
                  return (
                    <Box key={index} sx={{ display: 'inline-flex', alignItems: 'center', m: 0.5 }}>
                      <Chip
                        label={label}
                        onDelete={(e) => {
                          e.stopPropagation()
                          handleRemoveException(index)
                        }}
                        onClick={() => setExceptionDetailDialog({ open: true, exception, index })}
                        icon={exception.type === 'FilePublisherCondition' ? <VisibilityIcon /> : undefined}
                        sx={{ cursor: 'pointer' }}
                        color="warning"
                      />
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleEditException(index)
                        }}
                        sx={{ ml: 0.5 }}
                        color="primary"
                      >
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  )
                })
              )}
            </Grid>

            <Grid item xs={12}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>{editingExceptionIndex !== null ? `Edit Exception ${editingExceptionIndex + 1}` : 'Add Exception'}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Exceptions exclude specific paths, publishers, or file hashes from the rule conditions.
                    </Typography>
                    <FormControl fullWidth>
                      <InputLabel>Exception Type</InputLabel>
                      <Select
                        value={newException.type}
                        onChange={(e) => setNewException({ ...newException, type: e.target.value })}
                        label="Exception Type"
                      >
                        <MenuItem value="FilePathCondition">File Path</MenuItem>
                        <MenuItem value="FilePublisherCondition">File Publisher</MenuItem>
                        <MenuItem value="FileHashCondition">File Hash</MenuItem>
                      </Select>
                    </FormControl>

                    {newException.type === 'FilePathCondition' && (
                      <>
                        <TextField
                          fullWidth
                          label="Exception Path"
                          value={newException.path}
                          onChange={handleExceptionFieldChange('path')}
                          placeholder="%SYSTEM32%\\Tasks\\* or C:\\Temp\\*"
                          helperText="Path to exclude from the rule conditions"
                        />
                        {pathSuggestion.type === 'exception' && pathSuggestion.original === newException.path && (
                          <Alert 
                            severity="info" 
                            action={
                              <Box sx={{ display: 'flex', gap: 1 }}>
                                <Button size="small" onClick={handleAcceptSuggestion}>
                                  Use {pathSuggestion.suggested}
                                </Button>
                                <Button size="small" onClick={handleDismissSuggestion}>
                                  Keep original
                                </Button>
                              </Box>
                            }
                            sx={{ mt: 1 }}
                          >
                            <Typography variant="body2" sx={{ mb: 0.5 }}>
                              Trying to add: <code>{pathSuggestion.original}</code>
                            </Typography>
                            <Typography variant="body2">
                              Want to make it: <code style={{ fontWeight: 'bold' }}>{pathSuggestion.suggested}</code>?
                            </Typography>
                          </Alert>
                        )}
                      </>
                    )}

                    {newException.type === 'FilePublisherCondition' && (
                      <>
                        <TextField
                          fullWidth
                          label="Publisher Name"
                          value={newException.publisher_name}
                          onChange={handleExceptionFieldChange('publisher_name')}
                          placeholder="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US"
                          helperText="Publisher name (required)"
                          required
                        />
                        <TextField
                          fullWidth
                          label="Product Name"
                          value={newException.product_name}
                          onChange={handleExceptionFieldChange('product_name')}
                          placeholder="MICROSOFT® WINDOWS® OPERATING SYSTEM"
                          helperText="Product name (use * for any)"
                        />
                        <TextField
                          fullWidth
                          label="Binary Name"
                          value={newException.binary_name}
                          onChange={handleExceptionFieldChange('binary_name')}
                          placeholder="SENSECNCPROXY.EXE"
                          helperText="Binary name (use * for any)"
                        />
                        <FormControl fullWidth>
                          <InputLabel>Version Range Type</InputLabel>
                          <Select
                            value={newException.version_range_type}
                            onChange={(e) => setNewException({ ...newException, version_range_type: e.target.value })}
                            label="Version Range Type"
                          >
                            <MenuItem value="any">Any Version</MenuItem>
                            <MenuItem value="and_above">And Above</MenuItem>
                            <MenuItem value="and_below">And Below</MenuItem>
                            <MenuItem value="exactly">Exactly</MenuItem>
                          </Select>
                        </FormControl>
                        {newException.version_range_type !== 'any' && (
                          <TextField
                            fullWidth
                            label="Version"
                            value={newException.version_value}
                            onChange={handleExceptionFieldChange('version_value')}
                            placeholder="10.840.20348.587"
                            helperText={
                              newException.version_range_type === 'and_above' ? 'Minimum version (and above)' :
                              newException.version_range_type === 'and_below' ? 'Maximum version (and below)' :
                              'Exact version'
                            }
                            required
                          />
                        )}
                      </>
                    )}

                    {newException.type === 'FileHashCondition' && (
                      <>
                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
                          <TextField
                            fullWidth
                            label="File Hash (SHA256)"
                            value={newException.file_hash}
                            onChange={handleExceptionFieldChange('file_hash')}
                            placeholder="E4BF8DA2B31F81D58CDAEEA94C527D4FAC2A3255D2D4DA91BDA7B6C89F68A09B"
                            helperText="SHA256 hash value (without 0x prefix)"
                            required
                          />
                          <input
                            accept="*"
                            style={{ display: 'none' }}
                            id="hash-file-input-exception"
                            key={`exception-${hashFileInputKey}`}
                            type="file"
                            onChange={(e) => handleHashFileSelect(e, true)}
                          />
                          <Button
                            variant="outlined"
                            component="label"
                            htmlFor="hash-file-input-exception"
                            startIcon={loadingHash ? <CircularProgress size={16} /> : <FileUploadIcon />}
                            disabled={loadingHash}
                            sx={{ mt: 1, whiteSpace: 'nowrap' }}
                            title="Select a file to calculate its SHA256 hash"
                          >
                            {loadingHash ? 'Calculating...' : 'From File'}
                          </Button>
                        </Box>
                        <TextField
                          fullWidth
                          label="Source File Name"
                          value={newException.source_file_name}
                          onChange={handleExceptionFieldChange('source_file_name')}
                          placeholder="ielowutil.exe"
                          helperText="Original file name (optional)"
                        />
                        <TextField
                          fullWidth
                          label="Source File Length"
                          value={newException.source_file_length}
                          onChange={handleExceptionFieldChange('source_file_length')}
                          placeholder="241664"
                          helperText="File size in bytes (optional)"
                          type="number"
                        />
                      </>
                    )}

                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Button
                        variant="contained"
                        startIcon={editingExceptionIndex !== null ? <EditIcon /> : <AddIcon />}
                        onClick={handleAddException}
                      >
                        {editingExceptionIndex !== null ? 'Update Exception' : 'Add Exception'}
                      </Button>
                      {editingExceptionIndex !== null && (
                        <Button
                          variant="outlined"
                          onClick={handleCancelEditException}
                        >
                          Cancel
                        </Button>
                      )}
                    </Box>
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>
        </Box>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} variant="contained" color="primary">
          {rule ? 'Update' : 'Create'}
        </Button>
      </DialogActions>

      {/* Exception Detail Dialog */}
      <Dialog
        open={exceptionDetailDialog.open}
        onClose={() => setExceptionDetailDialog({ open: false, exception: null, index: null })}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Exception Details</DialogTitle>
        <DialogContent>
          {exceptionDetailDialog.exception && (
            <Box sx={{ mt: 2 }}>
              {exceptionDetailDialog.exception.type === 'FilePathCondition' && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Exception Type
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    File Path Condition
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Path
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace', mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.path || 'N/A'}
                  </Typography>
                </>
              )}

              {exceptionDetailDialog.exception.type === 'FilePublisherCondition' && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Exception Type
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    File Publisher Condition
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Publisher Name
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace', mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.publisher_name || 'N/A'}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Product Name
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.product_name || '*'}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Binary Name
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.binary_name || '*'}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Version Range
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    {(() => {
                      const exc = exceptionDetailDialog.exception
                      if (exc.version_range_type === 'and_above' && exc.version_value) {
                        return `And Above: ${exc.version_value}`
                      } else if (exc.version_range_type === 'and_below' && exc.version_value) {
                        return `And Below: ${exc.version_value}`
                      } else if (exc.version_range_type === 'exactly' && exc.version_value) {
                        return `Exactly: ${exc.version_value}`
                      } else if (exc.version && exc.version !== '*') {
                        return `Version: ${exc.version}`
                      } else {
                        return 'Any Version'
                      }
                    })()}
                  </Typography>
                </>
              )}

              {exceptionDetailDialog.exception.type === 'FileHashCondition' && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Exception Type
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    File Hash Condition
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Hash Type
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2 }}>
                    SHA256
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    File Hash
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace', mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.file_hash || 'N/A'}
                  </Typography>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Source File Name
                  </Typography>
                  <Typography variant="body1" sx={{ mb: 2, wordBreak: 'break-all' }}>
                    {exceptionDetailDialog.exception.source_file_name || 'N/A'}
                  </Typography>
                  {exceptionDetailDialog.exception.source_file_length && (
                    <>
                      <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                        Source File Length
                      </Typography>
                      <Typography variant="body1" sx={{ mb: 2 }}>
                        {exceptionDetailDialog.exception.source_file_length} bytes
                      </Typography>
                    </>
                  )}
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setExceptionDetailDialog({ open: false, exception: null, index: null })}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
    </Dialog>
  )
}

export default RuleForm

