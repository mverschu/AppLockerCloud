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
} from '@mui/material'
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material'
import { createRule, updateRule, getCollections } from '../services/api'

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
    version: '',
    file_hash: '',
    source_file_name: '',
  })
  const [newException, setNewException] = useState({
    type: 'FilePathCondition',
    path: '',
  })
  const [pathSuggestion, setPathSuggestion] = useState({ original: '', suggested: '', type: null }) // type: 'condition' or 'exception'

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
      newConditionObj = {
        type: 'FilePublisherCondition',
        publisher_name: condition.publisher_name,
        product_name: condition.product_name || null,
        binary_name: condition.binary_name || null,
        version: condition.version || '*',
      }
    } else if (condition.type === 'FileHashCondition') {
      if (!condition.file_hash || !condition.source_file_name) {
        alert('Please enter file hash and source file name')
        return
      }
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

  const handleAddException = () => {
    if (!newException.path) {
      alert('Please enter a path')
      return
    }
    
    const exceptionObj = {
      type: 'FilePathCondition',
      path: newException.path,
    }
    
    setFormData({
      ...formData,
      exceptions: [...formData.exceptions, exceptionObj],
    })
    
    setNewException({
      type: 'FilePathCondition',
      path: '',
    })
    setPathSuggestion({ original: '', suggested: '', type: null })
  }

  const handleRemoveException = (index) => {
    setFormData({
      ...formData,
      exceptions: formData.exceptions.filter((_, i) => i !== index),
    })
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
              {formData.conditions.map((condition, index) => (
                <Chip
                  key={index}
                  label={`${condition.type}: ${condition.path || condition.publisher_name || condition.file_hash || 'N/A'}`}
                  onDelete={() => handleRemoveCondition(index)}
                  sx={{ m: 0.5 }}
                />
              ))}
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
                        <TextField
                          fullWidth
                          label="Version (optional)"
                          value={newCondition.version}
                          onChange={handleConditionFieldChange('version')}
                          placeholder="*"
                        />
                      </>
                    )}

                    {newCondition.type === 'FileHashCondition' && (
                      <>
                        <TextField
                          fullWidth
                          label="File Hash (SHA256)"
                          value={newCondition.file_hash}
                          onChange={handleConditionFieldChange('file_hash')}
                          required
                          placeholder="A1B2C3D4..."
                        />
                        <TextField
                          fullWidth
                          label="Source File Name"
                          value={newCondition.source_file_name}
                          onChange={handleConditionFieldChange('source_file_name')}
                          required
                          placeholder="example.exe"
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
                  No exceptions. Exceptions exclude paths from the rule conditions.
                </Typography>
              ) : (
                formData.exceptions.map((exception, index) => (
                  <Chip
                    key={index}
                    label={`Exception: ${exception.path}`}
                    onDelete={() => handleRemoveException(index)}
                    sx={{ m: 0.5 }}
                    color="warning"
                  />
                ))
              )}
            </Grid>

            <Grid item xs={12}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography>Add Exception</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      Exceptions exclude specific paths from the rule. Only FilePathCondition exceptions are supported.
                    </Typography>
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
                    <Button
                      variant="outlined"
                      startIcon={<AddIcon />}
                      onClick={handleAddException}
                    >
                      Add Exception
                    </Button>
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
    </Dialog>
  )
}

export default RuleForm

