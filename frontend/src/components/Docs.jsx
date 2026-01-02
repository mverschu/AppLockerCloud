import React, { useState } from 'react'
import {
  Container,
  Typography,
  Box,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Button,
  TextField,
  Alert,
  AlertTitle,
  Link,
  List,
  ListItem,
  ListItemText,
  Stack,
} from '@mui/material'
import {
  ExpandMore as ExpandMoreIcon,
  ContentCopy as ContentCopyIcon,
  Cloud as CloudIcon,
  Computer as ComputerIcon,
  Info as InfoIcon,
} from '@mui/icons-material'

function Docs() {
  const [copiedText, setCopiedText] = useState('')

  const handleCopy = (text, label) => {
    navigator.clipboard.writeText(text)
    setCopiedText(label)
    setTimeout(() => setCopiedText(''), 2000)
  }

  const intuneScript = `# Get-IntuneAppLocker.ps1
# Reads Intune/MDM AppLocker policies and outputs either a readable table or full XML.

param(
    [switch]$Xml
)

$mdmRoot = "C:\\Windows\\System32\\AppLocker\\MDM"

# Function to load a single Policy file as XML
function Get-MDMPolicyXml {
    param([string]$filePath)

    if (-Not (Test-Path $filePath)) { return $null }

    try {
        # Read file as bytes and decode as Unicode
        $bytes = Get-Content -Path $filePath -Encoding Byte -ErrorAction Stop
        if ($bytes.Length -eq 0) { return $null }

        $text = [System.Text.Encoding]::Unicode.GetString($bytes) -replace "\`0",""
        [xml]$xmlDoc = $text
        return $xmlDoc
    }
    catch {
        Write-Warning ("Failed to read XML file " + $filePath + ": " + $_.Exception.Message)
        return $null
    }
}

# Find all Policy files
try {
    $policyFiles = Get-ChildItem -Path $mdmRoot -Recurse -Filter "Policy" -File -ErrorAction Stop
}
catch {
    Write-Warning ("Failed to access folder " + $mdmRoot + ": " + $_.Exception.Message)
    return
}

if ($policyFiles.Count -eq 0) {
    Write-Host "No AppLocker policies found under $mdmRoot"
    return
}

# Merge XML documents for -Xml output
$mergedXml = New-Object System.Xml.XmlDocument
$root = $mergedXml.CreateElement("AppLockerPolicy")
$mergedXml.AppendChild($root) | Out-Null

foreach ($file in $policyFiles) {
    $policyXml = Get-MDMPolicyXml -filePath $file.FullName
    if ($policyXml -ne $null) {
        foreach ($ruleCollection in $policyXml.SelectNodes("RuleCollection")) {
            $imported = $mergedXml.ImportNode($ruleCollection, $true)
            $root.AppendChild($imported) | Out-Null
        }
    }
}

if ($Xml) {
    # Output full merged XML
    $mergedXml.OuterXml
}
else {
    # Build table view
    $allRules = @()
    foreach ($ruleCollection in $mergedXml.SelectNodes("//RuleCollection")) {
        $ruleType = $ruleCollection.Type
        foreach ($rule in $ruleCollection.ChildNodes) {
            $allRules += [PSCustomObject]@{
                RuleType       = $ruleType
                RuleClass      = $rule.Name
                Name           = $rule.GetAttribute("Name")
                Action         = $rule.GetAttribute("Action")
                UserOrGroupSid = $rule.GetAttribute("UserOrGroupSid")
            }
        }
    }

    if ($allRules.Count -gt 0) {
        $allRules | Sort-Object RuleType, Name | Format-Table -AutoSize
    }
    else {
        Write-Host "No rules found in the Intune/MDM AppLocker policies."
    }
}`

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom sx={{ mb: 3 }}>
        Documentation
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph sx={{ mb: 4 }}>
        Learn how to retrieve AppLocker policies from your Windows machines without administrative rights.
      </Typography>

      <Alert severity="info" sx={{ mb: 4 }}>
        <AlertTitle>No Administrative Rights Required</AlertTitle>
        Both methods described below work without requiring administrator privileges, making them suitable for end users.
      </Alert>

      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Stack direction="row" spacing={2} alignItems="center">
            <CloudIcon color="primary" />
            <Typography variant="h6">Intune / MDM Managed Machines</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ mb: 3 }}>
            <Typography variant="body1" paragraph>
              For machines managed by Microsoft Intune or other MDM solutions, the standard PowerShell cmdlet{' '}
              <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5 }}>
                Get-AppLockerPolicy -Effective
              </Typography> only works with on-premises Group Policy-based AppLocker policies.
              Use the script below to view AppLocker policies deployed via Intune/MDM.
            </Typography>
          </Box>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Step 1: Download the PowerShell Script
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Download the <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5, display: 'inline' }}>
              Get-IntuneAppLocker.ps1
            </Typography> script from the <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5, display: 'inline' }}>
              /scripts
            </Typography> directory of this repository,
            or copy the script below.
          </Typography>

          <Paper variant="outlined" sx={{ p: 2, mb: 2, position: 'relative' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="caption" color="text.secondary">
                PowerShell Script
              </Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => handleCopy(intuneScript, 'script')}
                variant="outlined"
              >
                {copiedText === 'script' ? 'Copied!' : 'Copy'}
              </Button>
            </Box>
            <TextField
              fullWidth
              multiline
              value={intuneScript}
              variant="outlined"
              InputProps={{
                readOnly: true,
                sx: {
                  fontFamily: 'monospace',
                  fontSize: '0.875rem',
                },
              }}
              sx={{
                '& .MuiInputBase-root': {
                  backgroundColor: 'background.default',
                },
              }}
            />
          </Paper>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Step 2: Run the Script
          </Typography>
          <Typography variant="body2" paragraph>
            Open PowerShell (no admin rights required) and run:
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography component="code" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                .\\Get-IntuneAppLocker.ps1
              </Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => handleCopy('.\\Get-IntuneAppLocker.ps1', 'run')}
                variant="outlined"
              >
                {copiedText === 'run' ? 'Copied!' : 'Copy'}
              </Button>
            </Box>
          </Paper>
          <Typography variant="body2" color="text.secondary" paragraph>
            This will display a table view of all AppLocker rules currently applied to your machine.
          </Typography>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Step 3: Export as XML
          </Typography>
          <Typography variant="body2" paragraph>
            To export the policy as XML (for importing into this web app), run:
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography component="code" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                .\\Get-IntuneAppLocker.ps1 -Xml | Out-File -FilePath AppLockerPolicy.xml -Encoding UTF8
              </Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => handleCopy('.\\Get-IntuneAppLocker.ps1 -Xml | Out-File -FilePath AppLockerPolicy.xml -Encoding UTF8', 'export')}
                variant="outlined"
              >
                {copiedText === 'export' ? 'Copied!' : 'Copy'}
              </Button>
            </Box>
          </Paper>
          <Typography variant="body2" color="text.secondary" paragraph>
            This creates an <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5, display: 'inline' }}>
              AppLockerPolicy.xml
            </Typography> file that you can import into this web application using the "Import from File" option.
          </Typography>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Step 4: Import into Web App
          </Typography>
          <List>
            <ListItem>
              <ListItemText
                primary="1. Click the 'Import' button in the web app"
                secondary="Select 'Import from File' from the dropdown menu"
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="2. Select the exported XML file"
                secondary="Choose the AppLockerPolicy.xml file you created"
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="3. Review and edit your rules"
                secondary="The imported rules will appear in the rule list, ready for editing or export"
              />
            </ListItem>
          </List>

          <Alert severity="success" sx={{ mt: 2 }}>
            <Typography variant="body2">
              <strong>Tip:</strong> You can also copy the XML output directly and use the "Import from Text" option in the web app.
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Stack direction="row" spacing={2} alignItems="center">
            <ComputerIcon color="primary" />
            <Typography variant="h6">On-Premises Group Policy Machines</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ mb: 3 }}>
            <Typography variant="body1" paragraph>
              For machines managed by on-premises Active Directory Group Policy, you can use the built-in PowerShell cmdlet
              to retrieve AppLocker policies.
            </Typography>
          </Box>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            View Current Policy
          </Typography>
          <Typography variant="body2" paragraph>
            Open PowerShell (no admin rights required) and run:
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography component="code" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                Get-AppLockerPolicy -Effective | Format-List
              </Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => handleCopy('Get-AppLockerPolicy -Effective | Format-List', 'onprem-view')}
                variant="outlined"
              >
                {copiedText === 'onprem-view' ? 'Copied!' : 'Copy'}
              </Button>
            </Box>
          </Paper>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Export as XML
          </Typography>
          <Typography variant="body2" paragraph>
            To export the effective policy as XML:
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography component="code" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath AppLockerPolicy.xml -Encoding UTF8
              </Typography>
              <Button
                size="small"
                startIcon={<ContentCopyIcon />}
                onClick={() => handleCopy('Get-AppLockerPolicy -Effective -Xml | Out-File -FilePath AppLockerPolicy.xml -Encoding UTF8', 'onprem-export')}
                variant="outlined"
              >
                {copiedText === 'onprem-export' ? 'Copied!' : 'Copy'}
              </Button>
            </Box>
          </Paper>
          <Typography variant="body2" color="text.secondary" paragraph>
            This creates an <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5, display: 'inline' }}>
              AppLockerPolicy.xml
            </Typography> file that you can import into this web application.
          </Typography>

          <Divider sx={{ my: 3 }} />

          <Alert severity="info" sx={{ mt: 2 }}>
            <AlertTitle>Official Documentation</AlertTitle>
            <Typography variant="body2">
              For more information about the <Typography component="code" sx={{ fontFamily: 'monospace', backgroundColor: (theme) => theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.05)', px: 0.5, borderRadius: 0.5, display: 'inline' }}>
                Get-AppLockerPolicy
              </Typography> cmdlet, see the{' '}
              <Link
                href="https://learn.microsoft.com/en-us/powershell/module/applocker/get-applockerpolicy"
                target="_blank"
                rel="noopener noreferrer"
              >
                Microsoft Learn documentation
              </Link>
              .
            </Typography>
          </Alert>
        </AccordionDetails>
      </Accordion>

      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Stack direction="row" spacing={2} alignItems="center">
            <InfoIcon color="primary" />
            <Typography variant="h6">Additional Information</Typography>
          </Stack>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="h6" gutterBottom>
            Why These Methods Work Without Admin Rights
          </Typography>
          <Typography variant="body2" paragraph>
            Both methods read AppLocker policy files that are stored in locations accessible to standard users:
          </Typography>
          <List>
            <ListItem>
              <ListItemText
                primary="Intune/MDM Policies"
                secondary="Stored in C:\Windows\System32\AppLocker\MDM (readable by standard users)"
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="Group Policy Policies"
                secondary="The Get-AppLockerPolicy cmdlet reads from the local policy store, which doesn't require admin rights"
              />
            </ListItem>
          </List>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" gutterBottom>
            Troubleshooting
          </Typography>
          <Typography variant="body2" paragraph>
            If you encounter issues:
          </Typography>
          <List>
            <ListItem>
              <ListItemText
                primary="No policies found"
                secondary="This may indicate that no AppLocker policies have been deployed to your machine"
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="Access denied errors"
                secondary="Ensure you're running PowerShell (not as administrator) and that your user account has read access to the policy directories"
              />
            </ListItem>
            <ListItem>
              <ListItemText
                primary="Script execution policy"
                secondary="If you get an execution policy error, run: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser"
              />
            </ListItem>
          </List>
        </AccordionDetails>
      </Accordion>
    </Container>
  )
}

export default Docs

