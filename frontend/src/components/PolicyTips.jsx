import React, { useState } from 'react'
import {
  Box,
  Alert,
  AlertTitle,
  Typography,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Paper,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
} from '@mui/material'
import {
  Info as InfoIcon,
  ContentCopy as ContentCopyIcon,
} from '@mui/icons-material'

// Common bypass folders that should be protected
const BYPASS_FOLDERS = [
  { path: '%SYSTEM32%\\Tasks', display: 'C:\\Windows\\System32\\Tasks', perm: 'W' },
  { path: '%WINDIR%\\Tasks', display: 'C:\\Windows\\Tasks', perm: 'RW' },
  { path: '%WINDIR%\\tracing', display: 'C:\\Windows\\tracing', perm: 'RW' },
  { path: '%WINDIR%\\Registration\\CRMLog', display: 'C:\\Windows\\Registration\\CRMLog', perm: 'RW' },
  { path: '%SYSTEM32%\\spool\\drivers\\color', display: 'C:\\Windows\\System32\\spool\\drivers\\color', perm: 'RW' },
  { path: '%SYSTEM32%\\Tasks\\Microsoft\\Windows\\PLA\\System\\*', display: 'C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\PLA\\System\\*', perm: 'W' },
  { path: '%SYSTEM32%\\Tasks\\Microsoft\\Windows\\SyncCenter\\*', display: 'C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\*', perm: 'W' },
  { path: '%WINDIR%\\SysWOW64\\Tasks', display: 'C:\\Windows\\SysWOW64\\Tasks', perm: 'W' },
]

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

// Check if a path matches a bypass folder (handles wildcards and environment variables)
const pathMatchesBypass = (rulePath, bypassPath) => {
  const ruleNorm = normalizePath(rulePath)
  const bypassNorm = normalizePath(bypassPath)
  
  // Exact match
  if (ruleNorm === bypassNorm) return true
  
  // Check if rule path contains the bypass path
  if (ruleNorm.includes(bypassNorm)) return true
  
  // Check if bypass path is a subpath of rule path (with wildcards)
  if (ruleNorm.includes('*') && bypassNorm.startsWith(ruleNorm.replace('*', ''))) return true
  
  return false
}

// Get tips for a specific rule
export const getRuleTips = (rule) => {
  const tips = []
  
  // Safety checks
  if (!rule) return tips
  if (rule.action !== 'Allow') return tips
  if (!rule.conditions || !Array.isArray(rule.conditions)) return tips
  
  // Check if this is a Windows folder allow rule
  // Only match actual Windows system folders, not paths that just contain "windows" in the name
  const isWindowsRule = rule.conditions.some(cond => {
    if (!cond) return false
    const path = cond.path || ''
    if (!path) return false
    
    // Check for Windows environment variables
    if (path.includes('%WINDIR%') || path.includes('%SYSTEM32%')) {
      return true
    }
    
    // Check for explicit Windows paths (but not ProgramData\Microsoft\Windows Defender)
    const lowerPath = path.toLowerCase()
    if (lowerPath.includes('c:\\windows') || lowerPath.startsWith('windows\\')) {
      // Exclude Windows Defender in ProgramData
      if (!lowerPath.includes('programdata') && !lowerPath.includes('program data')) {
        return true
      }
    }
    
    // Check for System32 paths
    if (lowerPath.includes('system32') || lowerPath.includes('syswow64')) {
      return true
    }
    
    return false
  })
  
  if (isWindowsRule) {
    // Get existing exceptions (only FilePathCondition exceptions are relevant for path matching)
    const existingExceptions = (rule.exceptions || [])
      .filter(exc => exc.type === 'FilePathCondition')
      .map(exc => normalizePath(exc.path))
    
    // Find unprotected bypass folders
    const unprotectedFolders = BYPASS_FOLDERS.filter(bypass => {
      // Check if any exception already covers this bypass folder
      return !existingExceptions.some(excPath => {
        return pathMatchesBypass(excPath, bypass.path) || 
               pathMatchesBypass(excPath, bypass.display)
      })
    })
    
    if (unprotectedFolders.length > 0) {
      tips.push({
        type: 'warning',
        title: 'Windows Folder Bypass Risk',
        content: (
          <Box>
            <Typography variant="body2" sx={{ mb: 1 }}>
              This rule allows execution from Windows folders. Some folders have default write permissions that could allow bypasses:
            </Typography>
            <List dense sx={{ pl: 2, mb: 2 }}>
              {unprotectedFolders.map((folder, idx) => (
                <ListItem key={idx} disablePadding>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                        <Chip label={folder.perm} size="small" color="warning" />
                        <Typography variant="body2" component="code">
                          {folder.display}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
            <Typography variant="body2" sx={{ mb: 1 }}>
              To test which folders a low-privileged user can write to, use:
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <Paper
                component="code"
                sx={{
                  p: 1,
                  bgcolor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'grey.100',
                  fontFamily: 'monospace',
                  flex: 1,
                  fontSize: '0.875rem',
                }}
              >
                .\accesschk64.exe "lowprivuser" C:\Windows -wus
              </Paper>
              <IconButton
                size="small"
                onClick={() => {
                  navigator.clipboard.writeText('accesschk64.exe "lowprivuser" C:\\Windows -wus')
                }}
                title="Copy to clipboard"
              >
                <ContentCopyIcon fontSize="small" />
              </IconButton>
            </Box>
            <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
              Consider adding exceptions for these folders to prevent bypasses.
            </Typography>
          </Box>
        ),
      })
    }
  }
  
  // Check for wildcard allow rules
  const hasWildcard = rule.conditions && rule.conditions.some(cond => {
    if (!cond) return false
    const path = cond.path || ''
    return path === '*' || path === '*.*'
  })
  
  if (hasWildcard && rule.user_or_group_sid !== 'S-1-5-32-544') {
    tips.push({
      type: 'warning',
      title: 'Wildcard Allow Rule',
      content: (
        <Typography variant="body2">
          This rule allows execution from any path. This should typically be restricted to Administrators (S-1-5-32-544) only.
        </Typography>
      ),
    })
  }
  
  // Check for Appx rules that allow all signed packaged apps
  if (rule.action === 'Allow' && rule.collection === 'Appx') {
    const allowsAllSignedApps = rule.conditions && rule.conditions.some(cond => {
      if (!cond || cond.type !== 'FilePublisherCondition') return false
      return cond.publisher_name === '*' || cond.publisher_name === ''
    })
    
    if (allowsAllSignedApps) {
      tips.push({
        type: 'warning',
        title: 'Overly Permissive Packaged App Rule',
        content: (
          <Box>
            <Typography variant="body2" sx={{ mb: 1 }}>
              This rule allows all signed packaged apps from any publisher. This is a significant security risk as it allows execution of any store app that is signed, including potentially malicious ones like Python3, which can enable attackers to execute unwanted code without easy detection.
            </Typography>
            <Typography variant="body2" sx={{ mb: 1, fontWeight: 'medium' }}>
              Recommended security improvements:
            </Typography>
            <List dense sx={{ pl: 2, mb: 2 }}>
              <ListItem disablePadding>
                <ListItemText
                  primary={
                    <Typography variant="body2">
                      <strong>Option 1:</strong> Limit to Microsoft Corporation as the publisher. Change the Publisher Name from <code>*</code> to:
                    </Typography>
                  }
                  secondary={
                    <Box sx={{ pl: 2, mt: 0.5 }}>
                      <Typography variant="caption" component="div" sx={{ fontFamily: 'monospace' }}>
                        CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=WA, C=US
                      </Typography>
                    </Box>
                  }
                />
              </ListItem>
              <ListItem disablePadding sx={{ mt: 1 }}>
                <ListItemText
                  primary={
                    <Typography variant="body2">
                      <strong>Option 2:</strong> Deny everything and create explicit allow rules for only the packaged apps you need. This provides the strongest security posture.
                    </Typography>
                  }
                />
              </ListItem>
            </List>
            <Typography variant="body2" sx={{ fontStyle: 'italic' }}>
              The default rule allows any signed store app, which can be exploited by attackers to run code that appears legitimate but is not from trusted sources.
            </Typography>
          </Box>
        ),
      })
    }
  }
  
  // Check if rule allows Windows or Program Files execution (for living-off-the-land tip)
  // Only show this tip for Executable (Exe) collection rules and not for administrators
  const allowsWindows = rule.conditions && rule.conditions.some(cond => {
    if (!cond) return false
    const path = cond.path || ''
    if (!path) return false
    const lowerPath = path.toLowerCase()
    return path.includes('%WINDIR%') || 
           path.includes('%SYSTEM32%') ||
           lowerPath.includes('c:\\windows') ||
           path === '*' ||
           path === '*.*'
  })
  
  const allowsProgramFiles = rule.conditions && rule.conditions.some(cond => {
    if (!cond) return false
    const path = cond.path || ''
    if (!path) return false
    const lowerPath = path.toLowerCase()
    return path.includes('%PROGRAMFILES%') ||
           lowerPath.includes('c:\\program files') ||
           path === '*' ||
           path === '*.*'
  })
  
  // Only show living-off-the-land tip for Executable rules and not for administrators
  if (rule.action === 'Allow' && rule.collection === 'Exe' && rule.user_or_group_sid !== 'S-1-5-32-544') {
    const windowsBinaries = [
      {
        name: 'InstallUtil.exe',
        path: '%WINDIR%\\Microsoft.NET\\Framework*\\v*\\InstallUtil.exe',
        description: 'Used for installing .NET assemblies, commonly abused for code execution',
      },
      {
        name: 'mshta.exe',
        path: '%SYSTEM32%\\mshta.exe',
        description: 'Microsoft HTML Application host, can execute scripts',
      },
      {
        name: 'PresentationHost.exe',
        path: '%SYSTEM32%\\PresentationHost.exe',
        description: 'Windows Presentation Foundation host, can be abused',
      },
      {
        name: 'regasm.exe',
        path: '%WINDIR%\\Microsoft.NET\\Framework*\\v*\\regasm.exe',
        description: '.NET Assembly Registration Tool, can execute code',
      },
      {
        name: 'regsvcs.exe',
        path: '%WINDIR%\\Microsoft.NET\\Framework*\\v*\\regsvcs.exe',
        description: '.NET Services Installation Tool, can execute code',
      },
    ]
    
    const programFilesBinaries = [
      {
        name: 'MSBuild.exe',
        path: '%PROGRAMFILES%\\Microsoft Visual Studio*\\MSBuild*\\Bin\\MSBuild.exe',
        description: 'Microsoft Build Engine, can execute arbitrary code',
      },
    ]
    
    let livingOffTheLandBinaries = []
    let tipTitle = ''
    let tipDescription = ''
    
    if (allowsWindows && allowsProgramFiles) {
      // Show both Windows and Program Files binaries
      livingOffTheLandBinaries = [...windowsBinaries, ...programFilesBinaries]
      tipTitle = 'Living-Off-The-Land Binary Risk'
      tipDescription = 'This rule allows execution from Windows and Program Files directories. The following executables are commonly abused living-off-the-land binaries and should be considered for restriction for standard users:'
    } else if (allowsWindows) {
      // Show only Windows binaries
      livingOffTheLandBinaries = windowsBinaries
      tipTitle = 'Living-Off-The-Land Binary Risk (Windows)'
      tipDescription = 'This rule allows execution from Windows directories. The following executables are commonly abused living-off-the-land binaries and should be considered for restriction for standard users:'
    } else if (allowsProgramFiles) {
      // Show only Program Files binaries
      livingOffTheLandBinaries = programFilesBinaries
      tipTitle = 'Living-Off-The-Land Binary Risk (Program Files)'
      tipDescription = 'This rule allows execution from Program Files directories. The following executables are commonly abused living-off-the-land binaries and should be considered for restriction for standard users:'
    }
    
    // Filter out binaries that are already covered by exceptions (only FilePathCondition exceptions)
    if (livingOffTheLandBinaries.length > 0) {
      const existingExceptions = (rule.exceptions || [])
        .filter(exc => exc.type === 'FilePathCondition')
        .map(exc => normalizePath(exc.path))
      
      livingOffTheLandBinaries = livingOffTheLandBinaries.filter(binary => {
        // Check if any exception already covers this binary path
        return !existingExceptions.some(excPath => {
          return pathMatchesBypass(excPath, binary.path)
        })
      })
    }
    
    if (livingOffTheLandBinaries.length > 0) {
      tips.push({
        type: 'warning',
        title: tipTitle,
        content: (
          <Box>
            <Typography variant="body2" sx={{ mb: 1 }}>
              {tipDescription}
            </Typography>
            <List dense sx={{ pl: 2, mb: 2 }}>
              {livingOffTheLandBinaries.map((binary, idx) => (
                <ListItem key={idx} disablePadding>
                  <ListItemText
                    primary={
                      <Box>
                        <Typography variant="body2" component="span" sx={{ fontWeight: 'medium', fontFamily: 'monospace' }}>
                          {binary.name}
                        </Typography>
                        <Typography variant="body2" component="span" sx={{ ml: 1, color: 'text.secondary' }}>
                          - {binary.description}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      <Box sx={{ pl: 2, mt: 0.5 }}>
                        <Typography variant="caption" component="div" sx={{ fontFamily: 'monospace' }}>
                          Path: {binary.path}
                        </Typography>
                      </Box>
                    }
                  />
                </ListItem>
              ))}
            </List>
            <Typography variant="body2" sx={{ fontStyle: 'italic', mt: 1 }}>
              These binaries generally have no business requirement for execution by standard users. Consider adding exceptions to block them while preserving administrative functionality.
            </Typography>
          </Box>
        ),
        livingOffTheLandBinaries: livingOffTheLandBinaries, // Store for auto-apply functionality
      })
    }
  }
  
  // Check for hardcoded Windows paths that should use environment variables
  const pathMappings = [
    { hardcoded: /^[A-Z]:\\Windows\\System32/i, env: '%SYSTEM32%', example: 'C:\\Windows\\System32\\spool\\drivers\\color → %SYSTEM32%\\spool\\drivers\\color' },
    { hardcoded: /^[A-Z]:\\Windows/i, env: '%WINDIR%', example: 'C:\\Windows\\Tasks → %WINDIR%\\Tasks' },
    { hardcoded: /^[A-Z]:\\Program Files/i, env: '%PROGRAMFILES%', example: 'C:\\Program Files\\* → %PROGRAMFILES%\\*' },
    { hardcoded: /^[A-Z]:\\Program Files \(x86\)/i, env: '%PROGRAMFILES(X86)%', example: 'C:\\Program Files (x86)\\* → %PROGRAMFILES(X86)%\\*' },
    { hardcoded: /^[A-Z]:\\ProgramData/i, env: '%PROGRAMDATA%', example: 'C:\\ProgramData\\* → %PROGRAMDATA%\\*' },
  ]
  
  const hardcodedPaths = []
  rule.conditions && rule.conditions.forEach(cond => {
    if (!cond || !cond.path) return
    const path = cond.path
    
    // Skip if already using environment variables
    if (path.includes('%')) return
    
    // Check each mapping
    for (const mapping of pathMappings) {
      if (mapping.hardcoded.test(path)) {
        // Extract the part after the base path
        const match = path.match(mapping.hardcoded)
        if (match) {
          const remainingPath = path.substring(match[0].length).replace(/^\\/, '')
          const suggestedPath = remainingPath 
            ? `${mapping.env}\\${remainingPath}`
            : `${mapping.env}\\*`
          
          hardcodedPaths.push({
            original: path,
            suggested: suggestedPath,
            env: mapping.env,
          })
          break // Only match the first pattern
        }
      }
    }
  })
  
  if (hardcodedPaths.length > 0) {
    tips.push({
      type: 'info',
      title: 'Use Environment Variables',
      content: (
        <Box>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Consider using environment variables instead of hardcoded paths for better portability across different Windows installations:
          </Typography>
          <List dense sx={{ pl: 2 }}>
            {hardcodedPaths.map((item, idx) => (
              <ListItem key={idx} disablePadding>
                <ListItemText
                  primary={
                    <Box>
                      <Typography variant="body2" component="span" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                        {item.original}
                      </Typography>
                      <Typography variant="body2" component="span" sx={{ mx: 1 }}>→</Typography>
                      <Typography variant="body2" component="span" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', fontWeight: 'medium' }}>
                        {item.suggested}
                      </Typography>
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </Box>
      ),
    })
  }
  
  return tips
}

const PolicyTipsDialog = ({ open, onClose, rule, onRuleUpdate }) => {
  if (!rule) {
    return null
  }
  
  let tips = []
  try {
    tips = getRuleTips(rule)
  } catch (error) {
    console.error('Error getting rule tips:', error)
    return (
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogTitle>Policy Improvement Tips</DialogTitle>
        <DialogContent>
          <Alert severity="error">
            <AlertTitle>Error</AlertTitle>
            <Typography variant="body2">
              Failed to load tips: {error.message}
            </Typography>
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Close</Button>
        </DialogActions>
      </Dialog>
    )
  }
  
  if (tips.length === 0) {
    return null
  }
  
  const handleApplyExceptions = async () => {
    if (!rule || !onRuleUpdate) return
    
    // Find the Windows bypass tip
    const bypassTip = tips.find(tip => tip.title === 'Windows Folder Bypass Risk')
    if (!bypassTip) return
    
    // Extract unprotected folders from the tip content
    // The tip content has a List with unprotected folders
    const unprotectedFolders = BYPASS_FOLDERS.filter(bypass => {
      const existingExceptions = (rule.exceptions || []).map(exc => normalizePath(exc.path))
      return !existingExceptions.some(excPath => {
        return pathMatchesBypass(excPath, bypass.path) || 
               pathMatchesBypass(excPath, bypass.display)
      })
    })
    
    if (unprotectedFolders.length === 0) return
    
    // Add exceptions for unprotected folders
    const newExceptions = unprotectedFolders.map(folder => ({
      type: 'FilePathCondition',
      path: folder.path,
    }))
    
    // Merge with existing exceptions
    const updatedExceptions = [...(rule.exceptions || []), ...newExceptions]
    
    // Update the rule
    try {
      await onRuleUpdate(rule.id, {
        exceptions: updatedExceptions,
      })
      onClose()
    } catch (error) {
      console.error('Failed to apply exceptions:', error)
      alert('Failed to apply exceptions: ' + (error.response?.data?.detail || error.message))
    }
  }

  const handleApplyLivingOffTheLandExceptions = async () => {
    if (!rule || !onRuleUpdate) return
    
    // Find the living-off-the-land tip
    const lotlTip = tips.find(tip => tip.title && tip.title.includes('Living-Off-The-Land Binary Risk'))
    if (!lotlTip || !lotlTip.livingOffTheLandBinaries) return
    
    const binaries = lotlTip.livingOffTheLandBinaries
    
    // Add exceptions for all living-off-the-land binaries
    const newExceptions = binaries.map(binary => ({
      type: 'FilePathCondition',
      path: binary.path,
    }))
    
    // Check for duplicates
    const existingExceptions = (rule.exceptions || []).map(exc => normalizePath(exc.path))
    const uniqueExceptions = newExceptions.filter(newExc => {
      const newPath = normalizePath(newExc.path)
      return !existingExceptions.some(excPath => pathMatchesBypass(excPath, newPath))
    })
    
    if (uniqueExceptions.length === 0) {
      alert('All suggested exceptions are already added to this rule.')
      return
    }
    
    // Merge with existing exceptions
    const updatedExceptions = [...(rule.exceptions || []), ...uniqueExceptions]
    
    // Update the rule
    try {
      await onRuleUpdate(rule.id, {
        exceptions: updatedExceptions,
      })
      onClose()
    } catch (error) {
      console.error('Failed to apply living-off-the-land exceptions:', error)
      alert('Failed to apply exceptions: ' + (error.response?.data?.detail || error.message))
    }
  }

  const handleCreateRundll32DenyRule = async () => {
    try {
      if (onCreateRule) {
        // Use the onCreateRule callback if provided
        await onCreateRule({
          name: 'Block rundll32.exe for standard users',
          description: 'Prevents DLL execution bypass methods by blocking rundll32.exe for standard users',
          collection: 'Exe',
          action: 'Deny',
          user_or_group_sid: 'S-1-1-0', // Everyone (standard users)
          conditions: [
            {
              type: 'FilePathCondition',
              path: '%SYSTEM32%\\rundll32.exe',
            },
          ],
        })
        onClose()
      } else {
        // Fallback: import and use createRule directly
        const { createRule } = await import('../services/api')
        await createRule({
          name: 'Block rundll32.exe for standard users',
          description: 'Prevents DLL execution bypass methods by blocking rundll32.exe for standard users',
          collection: 'Exe',
          action: 'Deny',
          user_or_group_sid: 'S-1-1-0', // Everyone (standard users)
          conditions: [
            {
              type: 'FilePathCondition',
              path: '%SYSTEM32%\\rundll32.exe',
            },
          ],
        })
        alert('Successfully created deny rule for rundll32.exe in Executable collection. Please refresh to see the new rule.')
        onClose()
      }
    } catch (error) {
      console.error('Failed to create rundll32 deny rule:', error)
      alert('Failed to create deny rule: ' + (error.response?.data?.detail || error.message))
    }
  }
  
  // Check if there are exceptions that can be auto-applied
  const canApplyExceptions = tips.some(tip => tip.title === 'Windows Folder Bypass Risk')
  
  // Check if there's a living-off-the-land tip (can have different titles)
  const livingOffTheLandTip = tips.find(tip => tip.title && tip.title.includes('Living-Off-The-Land Binary Risk'))
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Policy Improvement Tips</DialogTitle>
      <DialogContent>
        <Box sx={{ mt: 1 }}>
          {tips.map((tip, index) => (
            <Alert key={index} severity={tip.type} sx={{ mb: 2 }}>
              <AlertTitle>{tip.title}</AlertTitle>
              {tip.content}
            </Alert>
          ))}
        </Box>
      </DialogContent>
      <DialogActions>
        {canApplyExceptions && onRuleUpdate && (
          <Button 
            onClick={handleApplyExceptions} 
            variant="contained" 
            color="primary"
            sx={{ mr: 1 }}
          >
            Add Bypass Folder Exceptions
          </Button>
        )}
        {livingOffTheLandTip && onRuleUpdate && (
          <Button 
            onClick={handleApplyLivingOffTheLandExceptions}
            variant="contained"
            color="warning"
            sx={{ mr: 1 }}
          >
            Add Living-Off-The-Land Exceptions
          </Button>
        )}
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  )
}

export default PolicyTipsDialog

