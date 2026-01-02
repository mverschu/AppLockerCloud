import React, { useState, useMemo, useEffect } from 'react'
import {
  Box,
  Container,
  Typography,
  Paper,
  TextField,
  Button,
  List,
  ListItem,
  ListItemText,
  Alert,
  AlertTitle,
  IconButton,
  Divider,
  Chip,
} from '@mui/material'
import {
  ContentCopy as ContentCopyIcon,
  Security as SecurityIcon,
} from '@mui/icons-material'
import { getRules } from '../services/storage'

// Convert environment variables to actual paths for command generation
const expandPath = (path) => {
  if (!path) return null
  
  // Replace environment variables with actual paths
  let expanded = path
    .replace(/%WINDIR%/gi, 'C:\\Windows')
    .replace(/%SYSTEM32%/gi, 'C:\\Windows\\System32')
    .replace(/%PROGRAMFILES%/gi, 'C:\\Program Files')
    .replace(/%PROGRAMFILES\(X86\)%/gi, 'C:\\Program Files (x86)')
    .replace(/%PROGRAMDATA%/gi, 'C:\\ProgramData')
    .replace(/%OSDRIVE%/gi, 'C:')
  
  // Remove wildcards for base path checking
  expanded = expanded.replace(/\\\*$/, '').replace(/\*$/, '')
  
  // Extract base directory (e.g., C:\Windows from C:\Windows\System32\something)
  const match = expanded.match(/^([A-Z]:\\(?:[^\\]+\\)*[^\\]+)/i)
  if (match) {
    return match[1]
  }
  
  return null
}

// Extract paths from rules that allow execution
const extractAllowedPaths = (rules) => {
  const paths = new Set()
  
  for (const rule of rules) {
    // Only check Allow rules
    if (rule.action !== 'Allow') continue
    
    // Check conditions for paths
    if (rule.conditions && Array.isArray(rule.conditions)) {
      for (const condition of rule.conditions) {
        if (condition.type === 'FilePathCondition' && condition.path) {
          const expanded = expandPath(condition.path)
          if (expanded) {
            paths.add(expanded)
            
            // If Program Files is allowed, also check Program Files (x86)
            if (expanded.toLowerCase().includes('program files') && 
                !expanded.toLowerCase().includes('(x86)')) {
              const x86Path = expanded.replace(/Program Files/i, 'Program Files (x86)')
              paths.add(x86Path)
            }
          }
        }
      }
    }
  }
  
  return Array.from(paths).sort()
}

// Normalize path for comparison (handle environment variables and case)
const normalizePath = (path) => {
  if (!path) return ''
  let normalized = path.replace(/\\/g, '/').toLowerCase()
  // Normalize environment variables
  normalized = normalized.replace(/%windir%/gi, '%windir%')
  normalized = normalized.replace(/%system32%/gi, '%system32%')
  normalized = normalized.replace(/%osdrive%/gi, '%osdrive%')
  return normalized
}

// Check if a path matches an exception path (handles wildcards and environment variables)
const pathMatchesException = (foundPath, exceptionPath) => {
  if (!foundPath || !exceptionPath) return false
  
  // Expand environment variables in exception path
  let expandedException = exceptionPath
    .replace(/%WINDIR%/gi, 'C:\\Windows')
    .replace(/%SYSTEM32%/gi, 'C:\\Windows\\System32')
    .replace(/%PROGRAMFILES%/gi, 'C:\\Program Files')
    .replace(/%PROGRAMFILES\(X86\)%/gi, 'C:\\Program Files (x86)')
    .replace(/%PROGRAMDATA%/gi, 'C:\\ProgramData')
    .replace(/%OSDRIVE%/gi, 'C:')
  
  // Normalize both paths (convert to forward slashes and lowercase for comparison)
  const foundNorm = foundPath.replace(/\\/g, '/').toLowerCase()
  let exceptionNorm = expandedException.replace(/\\/g, '/').toLowerCase()
  
  // Exact match
  if (foundNorm === exceptionNorm) return true
  
  // Remove trailing wildcards for base comparison
  const exceptionBase = exceptionNorm.replace(/\/\*$/, '').replace(/\*$/, '')
  
  // Check if found path is within exception path (exception is parent directory)
  // e.g., exception: C:\Windows\Tasks\* matches found: C:\Windows\Tasks\something
  if (exceptionBase && foundNorm.startsWith(exceptionBase + '/')) {
    return true
  }
  
  // Check if exception path exactly matches found path (without wildcard)
  if (foundNorm === exceptionBase) {
    return true
  }
  
  // Check if exception path is a subpath of found path (found is parent)
  // e.g., exception: C:\Windows\Tasks\subfolder matches found: C:\Windows\Tasks
  if (exceptionBase && exceptionBase.startsWith(foundNorm + '/')) {
    return true
  }
  
  // Check if exception is a parent with wildcard at the end
  // e.g., exception: C:\Windows\* matches found: C:\Windows\Tasks
  if (exceptionNorm.endsWith('/*') || exceptionNorm.endsWith('*')) {
    const parentPath = exceptionNorm.replace(/\/\*$/, '').replace(/\*$/, '')
    if (foundNorm.startsWith(parentPath + '/') || foundNorm === parentPath) {
      return true
    }
  }
  
  return false
}

// Collection types that need protection
const COLLECTION_TYPES = ['Exe', 'Script', 'Dll', 'Msi', 'Appx']

// Check if a path would be allowed by a rule (parent directory match)
const pathWouldBeAllowedByRule = (path, rulePath) => {
  if (!path || !rulePath) return false
  
  // Expand environment variables in rule path
  let expandedRule = rulePath
    .replace(/%WINDIR%/gi, 'C:\\Windows')
    .replace(/%SYSTEM32%/gi, 'C:\\Windows\\System32')
    .replace(/%PROGRAMFILES%/gi, 'C:\\Program Files')
    .replace(/%PROGRAMFILES\(X86\)%/gi, 'C:\\Program Files (x86)')
    .replace(/%PROGRAMDATA%/gi, 'C:\\ProgramData')
    .replace(/%OSDRIVE%/gi, 'C:')
  
  // Normalize paths
  const pathNorm = path.replace(/\\/g, '/').toLowerCase()
  let ruleNorm = expandedRule.replace(/\\/g, '/').toLowerCase()
  
  // Remove trailing wildcards
  ruleNorm = ruleNorm.replace(/\/\*$/, '').replace(/\*$/, '')
  
  // Check if path is within the rule path
  // e.g., rule: C:\Windows\* matches path: C:\Windows\Tasks
  if (pathNorm.startsWith(ruleNorm + '/') || pathNorm === ruleNorm) {
    return true
  }
  
  return false
}

// Check if a path is already covered by an exception in Allow rules
// Returns protection status for each collection type
const checkPathAgainstExceptions = (path, rules) => {
  const protectionStatus = {
    Exe: { isProtected: false, hasAllowRule: false, ruleName: null, exceptionPath: null, allowRuleName: null },
    Script: { isProtected: false, hasAllowRule: false, ruleName: null, exceptionPath: null, allowRuleName: null },
    Dll: { isProtected: false, hasAllowRule: false, ruleName: null, exceptionPath: null, allowRuleName: null },
    Msi: { isProtected: false, hasAllowRule: false, ruleName: null, exceptionPath: null, allowRuleName: null },
    Appx: { isProtected: false, hasAllowRule: false, ruleName: null, exceptionPath: null, allowRuleName: null },
  }
  
  // First pass: identify which collection types have Allow rules that would allow this path
  for (const rule of rules) {
    // Only check Allow rules
    if (rule.action !== 'Allow') continue
    
    // Get the collection type for this rule
    const collectionType = rule.collection
    if (!collectionType || !COLLECTION_TYPES.includes(collectionType)) continue
    
    // Check if this rule would allow the path (check conditions)
    if (rule.conditions && Array.isArray(rule.conditions)) {
      for (const condition of rule.conditions) {
        if (condition.type === 'FilePathCondition' && condition.path) {
          if (pathWouldBeAllowedByRule(path, condition.path)) {
            // This rule would allow execution from this path
            protectionStatus[collectionType].hasAllowRule = true
            protectionStatus[collectionType].allowRuleName = rule.name
            break
          }
        }
      }
    }
  }
  
  // Second pass: check if there are exceptions that block this path
  for (const rule of rules) {
    // Only check Allow rules
    if (rule.action !== 'Allow') continue
    
    // Get the collection type for this rule
    const collectionType = rule.collection
    if (!collectionType || !COLLECTION_TYPES.includes(collectionType)) continue
    
    // Only check exceptions if this rule would allow the path
    if (!protectionStatus[collectionType].hasAllowRule) continue
    
    // Check exceptions for this collection type
    if (rule.exceptions && Array.isArray(rule.exceptions)) {
      for (const exception of rule.exceptions) {
        if (exception.type === 'FilePathCondition' && exception.path) {
          if (pathMatchesException(path, exception.path)) {
            // Mark this collection type as protected (has exception blocking it)
            protectionStatus[collectionType].isProtected = true
            protectionStatus[collectionType].ruleName = rule.name
            protectionStatus[collectionType].exceptionPath = exception.path
            break
          }
        }
      }
    }
  }
  
  // Calculate overall protection status
  // Only consider collection types that have Allow rules (they need protection)
  const typesWithAllowRules = COLLECTION_TYPES.filter(type => protectionStatus[type].hasAllowRule)
  const protectedTypes = typesWithAllowRules.filter(type => protectionStatus[type].isProtected)
  const unprotectedTypes = typesWithAllowRules.filter(type => !protectionStatus[type].isProtected)
  const isFullyProtected = typesWithAllowRules.length > 0 && unprotectedTypes.length === 0
  const isPartiallyProtected = protectedTypes.length > 0 && unprotectedTypes.length > 0
  
  return {
    isProtected: isFullyProtected,
    isPartiallyProtected,
    protectionStatus,
    protectedTypes,
    unprotectedTypes,
    typesWithAllowRules,
  }
}

// Parse accesschk64.exe output
const parseAccesschkOutput = (output, rules) => {
  const results = []
  const lines = output.split('\n')
  const seenPaths = new Set()
  
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    
    // Skip lines that look like command prompts or headers
    if (trimmed.startsWith('>') || trimmed.startsWith('C:\\>') || 
        trimmed.toLowerCase().includes('accesschk') ||
        trimmed.toLowerCase().includes('access denied')) {
      continue
    }
    
    // Match patterns like:
    // RW C:\Windows\Tasks
    // W C:\Windows\tracing
    // R C:\Windows\something
    // Also handle cases with multiple spaces or tabs
    const match = trimmed.match(/^([RW]+)\s+([A-Z]:\\.+)$/i)
    if (match) {
      const permissions = match[1].toUpperCase()
      const path = match[2].trim()
      
      // Only include paths with write permissions (W or RW)
      // and avoid duplicates
      if (permissions.includes('W') && !seenPaths.has(path)) {
        seenPaths.add(path)
        
        // Check if this path is already covered by an exception
        const exceptionCheck = checkPathAgainstExceptions(path, rules)
        
        results.push({
          path,
          permissions,
          readOnly: !permissions.includes('W'),
          ...exceptionCheck,
        })
      }
    }
  }
  
  return results
}

const PolicyHardening = () => {
  const [rules, setRules] = useState([])
  const [outputText, setOutputText] = useState('')
  const [parsedResults, setParsedResults] = useState([])

  // Load rules on mount
  useEffect(() => {
    const loadRules = () => {
      try {
        const allRules = getRules()
        setRules(allRules)
      } catch (error) {
        console.error('Failed to load rules:', error)
      }
    }
    loadRules()
    
    // Listen for storage changes (when rules are updated)
    const handleStorageChange = () => {
      loadRules()
    }
    window.addEventListener('storage', handleStorageChange)
    
    // Also check periodically (for same-tab updates)
    const interval = setInterval(loadRules, 1000)
    
    return () => {
      window.removeEventListener('storage', handleStorageChange)
      clearInterval(interval)
    }
  }, [])

  // Extract paths that need checking
  const pathsToCheck = useMemo(() => {
    return extractAllowedPaths(rules)
  }, [rules])

  // Generate commands for each path
  const commands = useMemo(() => {
    return pathsToCheck.map(path => ({
      path,
      command: `accesschk64.exe "lowprivuser" "${path}" -wus`,
    }))
  }, [pathsToCheck])

  const handleParseOutput = () => {
    if (!outputText.trim()) {
      return
    }
    
    const results = parseAccesschkOutput(outputText, rules)
    setParsedResults(results)
  }

  const handleCopyCommand = (command) => {
    navigator.clipboard.writeText(command)
  }

  const handleCopyIcaclsCommand = (path) => {
    const command = `icacls "${path}"`
    navigator.clipboard.writeText(command)
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <SecurityIcon sx={{ fontSize: 40 }} />
        <Typography variant="h4" component="h1">
          Policy Hardening
        </Typography>
      </Box>

      <Alert severity="info" sx={{ mb: 3 }}>
        <AlertTitle>How to Use</AlertTitle>
        <Typography variant="body2">
          This tool helps you identify writable directories within paths allowed by your AppLocker policy. 
          Run the commands below on your Windows host as a low-privileged user, then paste the output here.
        </Typography>
      </Alert>

      {pathsToCheck.length === 0 ? (
        <Paper sx={{ p: 3 }}>
          <Typography variant="body1" color="text.secondary">
            No paths found in your Allow rules. Add some rules that allow execution from specific paths 
            (like C:\Windows or C:\Program Files) to see hardening commands here.
          </Typography>
        </Paper>
      ) : (
        <>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Step 1: Run These Commands
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Run these commands on your Windows host as a low-privileged user to check what directories 
              they can write to within the paths allowed by your policy:
            </Typography>
            
            {commands.map((cmd, idx) => (
              <Box key={idx} sx={{ mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Paper
                    component="code"
                    sx={{
                      p: 1.5,
                      bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'grey.100',
                      fontFamily: 'monospace',
                      flex: 1,
                      fontSize: '0.875rem',
                      wordBreak: 'break-all',
                    }}
                  >
                    {cmd.command}
                  </Paper>
                  <IconButton
                    size="small"
                    onClick={() => handleCopyCommand(cmd.command)}
                    title="Copy to clipboard"
                  >
                    <ContentCopyIcon fontSize="small" />
                  </IconButton>
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ ml: 1, mt: 0.5, display: 'block' }}>
                  Checking: {cmd.path}
                </Typography>
              </Box>
            ))}
          </Paper>

          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Step 2: Paste Output
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Paste the output from the commands above. The output should contain lines like:
            </Typography>
            <Box
              component="code"
              sx={{
                display: 'block',
                p: 1.5,
                mb: 2,
                bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'grey.100',
                fontFamily: 'monospace',
                fontSize: '0.875rem',
                whiteSpace: 'pre',
              }}
            >
              RW C:\Windows\Tasks{'\n'}RW C:\Windows\Temp{'\n'}W C:\Windows\tracing
            </Box>
            
            <TextField
              fullWidth
              multiline
              rows={10}
              value={outputText}
              onChange={(e) => setOutputText(e.target.value)}
              placeholder="Paste the output from accesschk64.exe here..."
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <Button
              variant="contained"
              onClick={handleParseOutput}
              disabled={!outputText.trim()}
            >
              Parse Output
            </Button>
          </Paper>

          {parsedResults.length > 0 && (
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Step 3: Review Writable Paths
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                The following paths were found to be writable by a low-privileged user:
              </Typography>
              
              <List>
                {parsedResults.map((result, idx) => (
                  <React.Fragment key={idx}>
                    <ListItem>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                            <Chip 
                              label={result.permissions} 
                              size="small" 
                              color={result.permissions.includes('W') ? 'warning' : 'default'}
                            />
                            <Typography variant="body1" component="code">
                              {result.path}
                            </Typography>
                            {result.isProtected && (
                              <Chip 
                                label="Fully Protected" 
                                size="small" 
                                color="success"
                              />
                            )}
                            {result.isPartiallyProtected && (
                              <Chip 
                                label="Partially Protected" 
                                size="small" 
                                color="warning"
                              />
                            )}
                            {result.typesWithAllowRules && result.typesWithAllowRules.length > 0 && result.unprotectedTypes && result.unprotectedTypes.length > 0 && !result.isPartiallyProtected && (
                              <Chip 
                                label="Missing Exceptions" 
                                size="small" 
                                color="error"
                              />
                            )}
                          </Box>
                        }
                        secondary={
                          <Box sx={{ mt: 1 }}>
                            {result.isProtected ? (
                              <Alert severity="success" sx={{ mb: 1 }}>
                                <AlertTitle>Fully Protected</AlertTitle>
                                <Typography variant="body2">
                                  This path is protected by exceptions across all collection types (Exe, Script, DLL, MSI, Appx). 
                                  AppLocker will block execution from this path for all file types.
                                </Typography>
                                {result.protectedTypes.length > 0 && (
                                  <Box sx={{ mt: 1 }}>
                                    <Typography variant="caption" component="div" sx={{ mb: 0.5 }}>
                                      Protected for: {result.protectedTypes.join(', ')}
                                    </Typography>
                                    {result.protectionStatus[result.protectedTypes[0]]?.ruleName && (
                                      <Typography variant="caption" component="div" sx={{ fontFamily: 'monospace' }}>
                                        Rule: {result.protectionStatus[result.protectedTypes[0]].ruleName}
                                      </Typography>
                                    )}
                                  </Box>
                                )}
                              </Alert>
                            ) : result.isPartiallyProtected ? (
                              <Alert severity="warning" sx={{ mb: 1 }}>
                                <AlertTitle>Partially Protected - Security Gap</AlertTitle>
                                <Typography variant="body2" sx={{ mb: 1 }}>
                                  This path is protected for some collection types but not all. This creates a security gap.
                                </Typography>
                                <Box sx={{ mb: 1 }}>
                                  <Typography variant="caption" component="div" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                                    Protected for: {result.protectedTypes.join(', ')}
                                  </Typography>
                                  {result.protectedTypes.map(type => {
                                    const status = result.protectionStatus[type]
                                    return status.isProtected ? (
                                      <Typography key={type} variant="caption" component="div" sx={{ ml: 1, fontFamily: 'monospace' }}>
                                        • {type}: {status.ruleName}
                                      </Typography>
                                    ) : null
                                  })}
                                </Box>
                                <Box>
                                  <Typography variant="caption" component="div" sx={{ fontWeight: 'bold', mb: 0.5, color: 'error.main' }}>
                                    NOT Protected for: {result.unprotectedTypes.join(', ')}
                                  </Typography>
                                  {result.unprotectedTypes.map(type => {
                                    const status = result.protectionStatus[type]
                                    return status.hasAllowRule ? (
                                      <Typography key={type} variant="caption" component="div" sx={{ ml: 1, fontFamily: 'monospace', color: 'error.main' }}>
                                        • {type}: Allow rule "{status.allowRuleName}" would allow this path - needs exception!
                                      </Typography>
                                    ) : null
                                  })}
                                  <Typography variant="body2" color="error" sx={{ mt: 1, fontWeight: 'bold' }}>
                                    ⚠️ Attackers could execute {result.unprotectedTypes.join(', ').toLowerCase()} files from this path!
                                  </Typography>
                                  <Typography variant="caption" component="div" sx={{ mt: 1 }}>
                                    Action required: Add exceptions for this path to the Allow rules listed above.
                                  </Typography>
                                </Box>
                              </Alert>
                            ) : (
                              <>
                                {result.typesWithAllowRules && result.typesWithAllowRules.length > 0 ? (
                                  <Alert severity="error" sx={{ mb: 1 }}>
                                    <AlertTitle>Security Gap - Missing Exceptions</AlertTitle>
                                    <Typography variant="body2" sx={{ mb: 1 }}>
                                      This path would be allowed by Allow rules but has no exceptions blocking it. 
                                      This is a security gap that needs to be addressed.
                                    </Typography>
                                    <Box sx={{ mb: 1 }}>
                                      <Typography variant="caption" component="div" sx={{ fontWeight: 'bold', mb: 0.5, color: 'error.main' }}>
                                        Missing exceptions for: {result.unprotectedTypes.join(', ')}
                                      </Typography>
                                      {result.unprotectedTypes.map(type => {
                                        const status = result.protectionStatus[type]
                                        return status.hasAllowRule ? (
                                          <Typography key={type} variant="caption" component="div" sx={{ ml: 1, fontFamily: 'monospace' }}>
                                            • {type}: Allow rule "{status.allowRuleName}" would allow this path - needs exception!
                                          </Typography>
                                        ) : null
                                      })}
                                    </Box>
                                    <Typography variant="body2" color="error" sx={{ fontWeight: 'bold' }}>
                                      ⚠️ Attackers could execute {result.unprotectedTypes.join(', ').toLowerCase()} files from this path!
                                    </Typography>
                                    <Typography variant="caption" component="div" sx={{ mt: 1 }}>
                                      Action required: Add an exception for this path to the Allow rules listed above.
                                    </Typography>
                                  </Alert>
                                ) : (
                                  <>
                                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                      Check if this path allows execution:
                                    </Typography>
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                      <Paper
                                        component="code"
                                        sx={{
                                          p: 1,
                                          bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'grey.100',
                                          fontFamily: 'monospace',
                                          fontSize: '0.875rem',
                                        }}
                                      >
                                        icacls "{result.path}"
                                      </Paper>
                                      <IconButton
                                        size="small"
                                        onClick={() => handleCopyIcaclsCommand(result.path)}
                                        title="Copy icacls command"
                                      >
                                        <ContentCopyIcon fontSize="small" />
                                      </IconButton>
                                    </Box>
                                    <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                      Look for execute permissions (RX, F, etc.) in the output. If found, consider adding 
                                      an exception to your AppLocker policy to block execution from this path.
                                    </Typography>
                                  </>
                                )}
                              </>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                    {idx < parsedResults.length - 1 && <Divider />}
                  </React.Fragment>
                ))}
              </List>
            </Paper>
          )}

          {parsedResults.length === 0 && outputText && (
            <Alert severity="warning" sx={{ mt: 2 }}>
              <AlertTitle>No Writable Paths Found</AlertTitle>
              <Typography variant="body2">
                The output was parsed but no writable paths were found. Make sure the output format matches:
              </Typography>
              <Box
                component="code"
                sx={{
                  display: 'block',
                  p: 1,
                  mt: 1,
                  bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'grey.100',
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                }}
              >
                RW C:\Windows\Tasks{'\n'}W C:\Windows\tracing
              </Box>
            </Alert>
          )}
        </>
      )}
    </Container>
  )
}

export default PolicyHardening

