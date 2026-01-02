import React, { useState } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Chip,
  Box,
  Typography,
  Tooltip,
} from '@mui/material'
import {
  Edit as EditIcon,
  Delete as DeleteIcon,
  Info as InfoIcon,
} from '@mui/icons-material'
import { deleteRule, updateRule } from '../services/api'
import PolicyTipsDialog, { getRuleTips } from './PolicyTips'

const RuleList = ({ rules, onEdit, onDelete }) => {
  const [tipsDialog, setTipsDialog] = useState({ open: false, rule: null })

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this rule?')) {
      try {
        await deleteRule(id)
        onDelete()
      } catch (error) {
        console.error('Failed to delete rule:', error)
      }
    }
  }

  const handleShowTips = (rule) => {
    setTipsDialog({ open: true, rule })
  }

  const handleCloseTips = () => {
    setTipsDialog({ open: false, rule: null })
  }

  const getCollectionColor = (collection) => {
    const colors = {
      Exe: 'primary',
      Script: 'secondary',
      Dll: 'success',
      Msi: 'warning',
      Appx: 'info',
    }
    return colors[collection] || 'default'
  }

  const getActionColor = (action) => {
    return action === 'Allow' ? 'success' : 'error'
  }

  if (!rules || !Array.isArray(rules) || rules.length === 0) {
    return (
      <Paper sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="h6" color="text.secondary">
          No rules found. Click "Add Rule" to create your first rule.
        </Typography>
      </Paper>
    )
  }

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Collection</TableCell>
            <TableCell>Action</TableCell>
            <TableCell>Description</TableCell>
            <TableCell>Conditions</TableCell>
            <TableCell>Exceptions</TableCell>
            <TableCell align="right">Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {rules.filter(rule => rule != null).map((rule) => (
            <TableRow key={rule.id} hover>
              <TableCell>
                <Typography variant="body2" fontWeight="medium">
                  {rule.name}
                </Typography>
              </TableCell>
              <TableCell>
                <Chip
                  label={rule.collection}
                  color={getCollectionColor(rule.collection)}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Chip
                  label={rule.action}
                  color={getActionColor(rule.action)}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2" color="text.secondary">
                  {rule.description || '-'}
                </Typography>
              </TableCell>
              <TableCell>
                {rule.conditions && Array.isArray(rule.conditions) && rule.conditions.length > 0 ? (
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {rule.conditions.map((condition, idx) => (
                      <Chip
                        key={idx}
                        label={condition?.type || 'Path'}
                        size="small"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    -
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                {rule.exceptions && Array.isArray(rule.exceptions) && rule.exceptions.length > 0 ? (
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {rule.exceptions.map((exception, idx) => {
                      let label = ''
                      if (exception?.type === 'FilePathCondition') {
                        label = exception.path || 'Path Exception'
                      } else if (exception?.type === 'FilePublisherCondition') {
                        label = `Publisher: ${exception.publisher_name || 'N/A'}`
                      } else if (exception?.type === 'FileHashCondition') {
                        const hash = exception.file_hash || ''
                        label = `Hash: ${hash.substring(0, 12)}... (${exception.hash_type || 'SHA256'})`
                      } else {
                        label = 'Exception'
                      }
                      return (
                        <Chip
                          key={idx}
                          label={label}
                          size="small"
                          variant="outlined"
                          color="warning"
                        />
                      )
                    })}
                  </Box>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    -
                  </Typography>
                )}
              </TableCell>
              <TableCell align="right">
                {(() => {
                  try {
                    if (rule && getRuleTips(rule).length > 0) {
                      return (
                        <Tooltip title="View improvement tips">
                          <IconButton
                            size="small"
                            onClick={() => handleShowTips(rule)}
                            color="warning"
                          >
                            <InfoIcon />
                          </IconButton>
                        </Tooltip>
                      )
                    }
                    return null
                  } catch (error) {
                    console.error('Error getting rule tips:', error)
                    return null
                  }
                })()}
                <IconButton
                  size="small"
                  onClick={() => onEdit(rule)}
                  color="primary"
                >
                  <EditIcon />
                </IconButton>
                <IconButton
                  size="small"
                  onClick={() => handleDelete(rule.id)}
                  color="error"
                >
                  <DeleteIcon />
                </IconButton>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <PolicyTipsDialog
        open={tipsDialog.open}
        onClose={handleCloseTips}
        rule={tipsDialog.rule}
        onRuleUpdate={async (ruleId, updates) => {
          try {
            await updateRule(ruleId, updates)
            onDelete() // Refresh the rules list
          } catch (error) {
            throw error
          }
        }}
      />
    </TableContainer>
  )
}

export default RuleList

