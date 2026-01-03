import React, { useState, useEffect } from 'react'
import {
  Box,
  Paper,
  Typography,
  Alert,
  AlertTitle,
  List,
  ListItem,
  ListItemText,
  Chip,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tabs,
  Tab,
  IconButton,
  Collapse,
} from '@mui/material'
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  PlayArrow as PlayArrowIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material'
import { validateAllRules, testPolicy, simulatePolicy } from '../services/ruleValidator'
import { getRules } from '../services/storage'

const ValidationPanel = ({ rules, onRuleClick }) => {
  const [validationResults, setValidationResults] = useState(null)
  const [selectedTab, setSelectedTab] = useState(0)
  const [expandedErrors, setExpandedErrors] = useState({})
  const [testDialogOpen, setTestDialogOpen] = useState(false)
  const [testCases, setTestCases] = useState([
    { path: 'C:\\Windows\\Tasks\\malware.exe', collection: 'Exe', userSid: 'S-1-1-0' },
  ])
  const [simulationResults, setSimulationResults] = useState([])

  useEffect(() => {
    if (rules && rules.length > 0) {
      const results = validateAllRules(rules)
      setValidationResults(results)
    } else {
      setValidationResults(null)
    }
  }, [rules])

  const handleTabChange = (event, newValue) => {
    setSelectedTab(newValue)
  }

  const handleToggleError = (index) => {
    setExpandedErrors(prev => ({
      ...prev,
      [index]: !prev[index],
    }))
  }

  const handleRunTest = () => {
    // Filter out empty test cases
    const validTestCases = testCases.filter(tc => tc.path && tc.path.trim() !== '')
    if (validTestCases.length === 0) {
      alert('Please add at least one test case with a file path')
      return
    }
    const results = simulatePolicy(rules, validTestCases)
    setSimulationResults(results)
    // Results are shown in the same tab (Test Mode is tab 3)
  }

  const handleAddTestCase = () => {
    setTestCases([...testCases, { path: '', collection: 'Exe', userSid: 'S-1-1-0' }])
  }

  const handleTestCaseChange = (index, field, value) => {
    const updated = [...testCases]
    updated[index] = { ...updated[index], [field]: value }
    setTestCases(updated)
  }

  const handleRemoveTestCase = (index) => {
    setTestCases(testCases.filter((_, i) => i !== index))
  }

  if (!validationResults) {
    return (
      <Paper sx={{ p: 3 }}>
        <Typography variant="body1" color="text.secondary">
          No rules to validate. Add some rules to see validation results.
        </Typography>
      </Paper>
    )
  }

  const { valid, errors, warnings, conflicts } = validationResults

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {valid ? (
              <CheckCircleIcon color="success" sx={{ fontSize: 40 }} />
            ) : (
              <ErrorIcon color="error" sx={{ fontSize: 40 }} />
            )}
            <Box>
              <Typography variant="h6">
                Policy Validation
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {valid ? 'Policy is valid' : 'Policy has issues that need attention'}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Chip
              label={`${errors.length} Errors`}
              color={errors.length > 0 ? 'error' : 'default'}
              size="small"
            />
            <Chip
              label={`${warnings.length} Warnings`}
              color={warnings.length > 0 ? 'warning' : 'default'}
              size="small"
            />
            <Chip
              label={`${conflicts.length} Conflicts`}
              color={conflicts.length > 0 ? 'error' : 'default'}
              size="small"
            />
          </Box>
        </Box>

        <Tabs value={selectedTab} onChange={handleTabChange} sx={{ mb: 2 }}>
          <Tab label="Errors" />
          <Tab label="Warnings" />
          <Tab label="Conflicts" />
          <Tab label="Test Mode" />
        </Tabs>

        {selectedTab === 0 && (
          <Box>
            {errors.length === 0 ? (
              <Alert severity="success">
                No errors found. All rules are properly configured.
              </Alert>
            ) : (
              <List>
                {errors.map((error, index) => (
                  <ListItem
                    key={index}
                    sx={{
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      border: '1px solid',
                      borderColor: 'error.main',
                      borderRadius: 1,
                      mb: 1,
                      p: 2,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', mb: 1 }}>
                      <ErrorIcon color="error" sx={{ mr: 1 }} />
                      <Typography variant="body1" fontWeight="medium">
                        {error.ruleName || 'Unknown Rule'}
                      </Typography>
                      {onRuleClick && error.ruleId && (
                        <Button
                          size="small"
                          onClick={() => onRuleClick(error.ruleId)}
                          sx={{ ml: 'auto' }}
                        >
                          View Rule
                        </Button>
                      )}
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Field:</strong> {error.field}
                    </Typography>
                    <Typography variant="body2" color="error">
                      {error.message}
                    </Typography>
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        )}

        {selectedTab === 1 && (
          <Box>
            {warnings.length === 0 ? (
              <Alert severity="info">
                No warnings found.
              </Alert>
            ) : (
              <List>
                {warnings.map((warning, index) => (
                  <ListItem
                    key={index}
                    sx={{
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      border: '1px solid',
                      borderColor: 'warning.main',
                      borderRadius: 1,
                      mb: 1,
                      p: 2,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', mb: 1 }}>
                      <WarningIcon color="warning" sx={{ mr: 1 }} />
                      <Typography variant="body1" fontWeight="medium">
                        {warning.ruleName || 'Unknown Rule'}
                      </Typography>
                      {onRuleClick && warning.ruleId && (
                        <Button
                          size="small"
                          onClick={() => onRuleClick(warning.ruleId)}
                          sx={{ ml: 'auto' }}
                        >
                          View Rule
                        </Button>
                      )}
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Field:</strong> {warning.field}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {warning.message}
                    </Typography>
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        )}

        {selectedTab === 2 && (
          <Box>
            {conflicts.length === 0 ? (
              <Alert severity="success">
                No conflicts detected. Rules do not overlap.
              </Alert>
            ) : (
              <List>
                {conflicts.map((conflict, index) => (
                  <ListItem
                    key={index}
                    sx={{
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      border: '1px solid',
                      borderColor: 'error.main',
                      borderRadius: 1,
                      mb: 1,
                      p: 2,
                    }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', mb: 1 }}>
                      <ErrorIcon color="error" sx={{ mr: 1 }} />
                      <Typography variant="body1" fontWeight="medium" color="error">
                        Conflict Detected
                      </Typography>
                    </Box>
                    <Typography variant="body2" sx={{ mb: 1 }}>
                      {conflict.message}
                    </Typography>
                    <Box sx={{ display: 'flex', gap: 2, mb: 1 }}>
                      <Chip
                        label={`${conflict.rule1.action}: ${conflict.rule1.name}`}
                        color={conflict.rule1.action === 'Allow' ? 'success' : 'error'}
                        size="small"
                        onClick={() => onRuleClick && onRuleClick(conflict.rule1.id)}
                        sx={{ cursor: 'pointer' }}
                      />
                      <Chip
                        label={`${conflict.rule2.action}: ${conflict.rule2.name}`}
                        color={conflict.rule2.action === 'Allow' ? 'success' : 'error'}
                        size="small"
                        onClick={() => onRuleClick && onRuleClick(conflict.rule2.id)}
                        sx={{ cursor: 'pointer' }}
                      />
                    </Box>
                    {conflict.details && (
                      <Typography variant="caption" color="text.secondary">
                        {conflict.details}
                      </Typography>
                    )}
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        )}

        {selectedTab === 3 && (
          <Box>
            <Alert severity="info" sx={{ mb: 2 }}>
              <AlertTitle>Test Mode</AlertTitle>
              Test how your policy would handle specific file paths. Add test cases and see if they would be allowed or denied.
            </Alert>

            <Box sx={{ mb: 2 }}>
              <Typography variant="h6" gutterBottom>
                Test Cases
              </Typography>
              {testCases.map((testCase, index) => (
                <Paper key={index} sx={{ p: 2, mb: 1 }}>
                  <Box sx={{ display: 'flex', gap: 1, mb: 1 }}>
                    <TextField
                      label="File Path"
                      value={testCase.path}
                      onChange={(e) => handleTestCaseChange(index, 'path', e.target.value)}
                      size="small"
                      fullWidth
                      placeholder="C:\\Windows\\System32\\notepad.exe"
                    />
                    <TextField
                      label="Collection"
                      value={testCase.collection}
                      onChange={(e) => handleTestCaseChange(index, 'collection', e.target.value)}
                      size="small"
                      select
                      SelectProps={{ native: true }}
                      sx={{ minWidth: 120 }}
                    >
                      <option value="Exe">Exe</option>
                      <option value="Script">Script</option>
                      <option value="Dll">Dll</option>
                      <option value="Msi">Msi</option>
                      <option value="Appx">Appx</option>
                    </TextField>
                    <TextField
                      label="User SID"
                      value={testCase.userSid}
                      onChange={(e) => handleTestCaseChange(index, 'userSid', e.target.value)}
                      size="small"
                      placeholder="S-1-1-0"
                      sx={{ minWidth: 150 }}
                    />
                    <IconButton
                      onClick={() => handleRemoveTestCase(index)}
                      color="error"
                      size="small"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </Paper>
              ))}
              <Button
                variant="outlined"
                onClick={handleAddTestCase}
                sx={{ mt: 1 }}
              >
                Add Test Case
              </Button>
            </Box>

            <Button
              variant="contained"
              startIcon={<PlayArrowIcon />}
              onClick={handleRunTest}
              disabled={testCases.length === 0}
              sx={{ mb: 2 }}
            >
              Run Tests
            </Button>

            {simulationResults.length > 0 && (
              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Path</TableCell>
                      <TableCell>Collection</TableCell>
                      <TableCell>Result</TableCell>
                      <TableCell>Reason</TableCell>
                      <TableCell>Matching Rules</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {simulationResults.map((result, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Typography variant="body2" component="code">
                            {result.path}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={result.collection} size="small" />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={result.result.allowed ? 'Allowed' : result.result.denied ? 'Denied' : 'Denied (Default)'}
                            color={result.result.allowed ? 'success' : 'error'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" color="text.secondary">
                            {result.result.reason}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {result.result.matchingRules.length > 0 ? (
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                              {result.result.matchingRules.map((rule, idx) => (
                                <Chip
                                  key={idx}
                                  label={rule.name}
                                  size="small"
                                  variant="outlined"
                                  onClick={() => onRuleClick && onRuleClick(rule.id)}
                                  sx={{ cursor: 'pointer' }}
                                />
                              ))}
                            </Box>
                          ) : (
                            <Typography variant="caption" color="text.secondary">
                              None
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )}
      </Paper>
    </Box>
  )
}

export default ValidationPanel

