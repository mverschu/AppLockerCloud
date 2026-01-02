import React, { useState, useEffect, useMemo } from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import {
  Container,
  AppBar,
  Toolbar,
  Typography,
  Box,
  Tabs,
  Tab,
  Button,
  Snackbar,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Menu,
  MenuItem,
} from '@mui/material'
import {
  Download as DownloadIcon,
  Upload as UploadIcon,
  Add as AddIcon,
  CloudDownload as CloudDownloadIcon,
  ArrowDropDown as ArrowDropDownIcon,
  ContentCopy as ContentCopyIcon,
  Delete as DeleteIcon,
  MenuBook as MenuBookIcon,
} from '@mui/icons-material'
import RuleList from './components/RuleList'
import RuleForm from './components/RuleForm'
import Docs from './components/Docs'
import { getRules, exportXML, importXML, importDefaultRules, exportCollectionXML, deleteAllRules } from './services/api'

function PolicyCreator() {
  const [rules, setRules] = useState([])
  const [selectedTab, setSelectedTab] = useState(0)
  const [openForm, setOpenForm] = useState(false)
  const [editingRule, setEditingRule] = useState(null)
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' })
  const [openImportDialog, setOpenImportDialog] = useState(false)
  const [importXmlText, setImportXmlText] = useState('')
  const [importMenuAnchor, setImportMenuAnchor] = useState(null)
  const [openExportDialog, setOpenExportDialog] = useState(false)
  const [exportXmlText, setExportXmlText] = useState('')
  const [exportMenuAnchor, setExportMenuAnchor] = useState(null)
  const [clearConfirmDialog, setClearConfirmDialog] = useState({ open: false, collection: null })

  useEffect(() => {
    loadRules()
  }, [])

  const loadRules = async () => {
    try {
      const data = await getRules()
      setRules(data)
    } catch (error) {
      showSnackbar('Failed to load rules', 'error')
    }
  }

  const handleTabChange = (event, newValue) => {
    setSelectedTab(newValue)
  }

  const handleAddRule = () => {
    setEditingRule(null)
    setOpenForm(true)
  }

  const handleEditRule = (rule) => {
    setEditingRule(rule)
    setOpenForm(true)
  }

  const handleFormClose = () => {
    setOpenForm(false)
    setEditingRule(null)
    loadRules()
  }

  const handleExport = async (asText = false, collectionType = null) => {
    try {
      let xml
      let filename
      
      if (collectionType) {
        xml = await exportCollectionXML(collectionType)
        filename = `AppLocker_${collectionType}.xml`
      } else {
        xml = await exportXML(rules)
        filename = 'AppLockerPolicy.xml'
      }
      
      if (asText) {
        setExportXmlText(xml)
        setOpenExportDialog(true)
      } else {
        const blob = new Blob([xml], { type: 'application/xml' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
        showSnackbar('Policy exported successfully', 'success')
      }
    } catch (error) {
      showSnackbar('Failed to export policy: ' + (error.response?.data?.detail || error.message), 'error')
    }
  }

  const handleExportMenuOpen = (event) => {
    setExportMenuAnchor(event.currentTarget)
  }

  const handleExportMenuClose = () => {
    setExportMenuAnchor(null)
  }

  const handleCopyExportText = () => {
    navigator.clipboard.writeText(exportXmlText)
    showSnackbar('XML copied to clipboard', 'success')
  }

  const handleImport = async (event) => {
    const file = event.target.files[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = async (e) => {
      try {
        const xmlContent = e.target.result
        const result = await importXML(xmlContent)
        const message = result.message || 'Policy imported successfully'
        showSnackbar(message, 'success')
        loadRules()
      } catch (error) {
        showSnackbar('Failed to import policy: ' + (error.response?.data?.detail || error.message), 'error')
      }
    }
    reader.readAsText(file)
    event.target.value = ''
  }

  const handleImportFromText = () => {
    setImportMenuAnchor(null)
    setImportXmlText('')
    setOpenImportDialog(true)
  }

  const handleImportTextSubmit = async () => {
    if (!importXmlText.trim()) {
      showSnackbar('Please enter XML content', 'error')
      return
    }

    try {
      const result = await importXML(importXmlText)
      const message = result.message || 'Policy imported successfully'
      showSnackbar(message, 'success')
      setOpenImportDialog(false)
      setImportXmlText('')
      loadRules()
    } catch (error) {
      showSnackbar('Failed to import policy: ' + (error.response?.data?.detail || error.message), 'error')
    }
  }

  const handleImportMenuOpen = (event) => {
    setImportMenuAnchor(event.currentTarget)
  }

  const handleImportMenuClose = () => {
    setImportMenuAnchor(null)
  }

  const handleImportDefaults = async () => {
    try {
      const collectionMap = {
        0: null,
        1: 'Exe',
        2: 'Script',
        3: 'Dll',
        4: 'Msi',
        5: 'Appx',
      }
      
      const collectionType = collectionMap[selectedTab]
      const result = await importDefaultRules(collectionType)
      
      const message = result.message || (collectionType 
        ? `Default ${collectionType} rules imported successfully`
        : 'All default rules imported successfully')
      showSnackbar(message, 'success')
      loadRules()
    } catch (error) {
      showSnackbar('Failed to import default rules: ' + (error.response?.data?.detail || error.message), 'error')
      console.error('Import default rules error:', error)
    }
  }

  const showSnackbar = (message, severity = 'success') => {
    setSnackbar({ open: true, message, severity })
  }

  const handleSnackbarClose = () => {
    setSnackbar({ ...snackbar, open: false })
  }

  const handleClearRules = (tabIndex = null) => {
    const collectionMap = {
      0: null,
      1: 'Exe',
      2: 'Script',
      3: 'Dll',
      4: 'Msi',
      5: 'Appx',
    }
    const collectionType = tabIndex !== null ? collectionMap[tabIndex] : null
    setClearConfirmDialog({ open: true, collection: collectionType })
  }

  const handleConfirmClear = async () => {
    try {
      await deleteAllRules(clearConfirmDialog.collection)
      const message = clearConfirmDialog.collection
        ? `All ${clearConfirmDialog.collection} rules cleared successfully`
        : 'All rules cleared successfully'
      showSnackbar(message, 'success')
      setClearConfirmDialog({ open: false, collection: null })
      loadRules()
    } catch (error) {
      showSnackbar('Failed to clear rules: ' + (error.response?.data?.detail || error.message), 'error')
    }
  }

  const handleCancelClear = () => {
    setClearConfirmDialog({ open: false, collection: null })
  }

  const filteredRules = useMemo(() => {
    if (!rules || rules.length === 0) return []
    if (selectedTab === 0) return rules
    const collectionMap = {
      1: 'Exe',
      2: 'Script',
      3: 'Dll',
      4: 'Msi',
      5: 'Appx',
    }
    const targetCollection = collectionMap[selectedTab]
    if (!targetCollection) return []
    return rules.filter(rule => rule && rule.collection === targetCollection)
  }, [rules, selectedTab])

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component={Link} to="/" sx={{ flexGrow: 1, textDecoration: 'none', color: 'inherit' }}>
            AppLocker Policy Creator
          </Typography>
          <input
            accept=".xml"
            style={{ display: 'none' }}
            id="import-button-file"
            type="file"
            onChange={handleImport}
          />
          <Button
            color="inherit"
            startIcon={<UploadIcon />}
            endIcon={<ArrowDropDownIcon />}
            onClick={handleImportMenuOpen}
            sx={{ mr: 1 }}
          >
            Import
          </Button>
          <Menu
            anchorEl={importMenuAnchor}
            open={Boolean(importMenuAnchor)}
            onClose={handleImportMenuClose}
          >
            <label htmlFor="import-button-file">
              <MenuItem component="span" onClick={handleImportMenuClose}>
                <UploadIcon sx={{ mr: 1, fontSize: 20 }} />
                Import from File
              </MenuItem>
            </label>
            <MenuItem onClick={handleImportFromText}>
              <UploadIcon sx={{ mr: 1, fontSize: 20 }} />
              Import from Text
            </MenuItem>
          </Menu>
          <Button
            color="inherit"
            startIcon={<CloudDownloadIcon />}
            onClick={handleImportDefaults}
            sx={{ mr: 1 }}
          >
            Import Defaults
          </Button>
          <Button
            color="inherit"
            startIcon={<DeleteIcon />}
            onClick={() => handleClearRules(selectedTab)}
            disabled={!filteredRules || filteredRules.length === 0}
            sx={{ mr: 1 }}
          >
            {selectedTab === 0 ? 'Clear All Rules' : (() => {
              const collectionMap = {
                1: 'Exe',
                2: 'Script',
                3: 'Dll',
                4: 'Msi',
                5: 'Appx',
              }
              return `Clear ${collectionMap[selectedTab] || 'Collection'} Rules`
            })()}
          </Button>
          <Button
            color="inherit"
            startIcon={<DownloadIcon />}
            endIcon={<ArrowDropDownIcon />}
            onClick={handleExportMenuOpen}
            disabled={rules.length === 0}
            sx={{ mr: 1 }}
          >
            Export XML
          </Button>
          <Menu
            anchorEl={exportMenuAnchor}
            open={Boolean(exportMenuAnchor)}
            onClose={handleExportMenuClose}
          >
            <MenuItem onClick={() => { handleExportMenuClose(); handleExport(false, null); }}>
              <DownloadIcon sx={{ mr: 1, fontSize: 20 }} />
              Export All as File
            </MenuItem>
            <MenuItem onClick={() => { handleExportMenuClose(); handleExport(true, null); }}>
              <ContentCopyIcon sx={{ mr: 1, fontSize: 20 }} />
              Export All as Text
            </MenuItem>
            {selectedTab > 0 && (() => {
              const collectionMap = {
                1: 'Exe',
                2: 'Script',
                3: 'Dll',
                4: 'Msi',
                5: 'Appx',
              }
              const collectionType = collectionMap[selectedTab]
              return (
                <>
                  <MenuItem onClick={() => { handleExportMenuClose(); handleExport(false, collectionType); }}>
                    <DownloadIcon sx={{ mr: 1, fontSize: 20 }} />
                    Export {collectionType} as File
                  </MenuItem>
                  <MenuItem onClick={() => { handleExportMenuClose(); handleExport(true, collectionType); }}>
                    <ContentCopyIcon sx={{ mr: 1, fontSize: 20 }} />
                    Export {collectionType} as Text
                  </MenuItem>
                </>
              )
            })()}
          </Menu>
          <Button
            color="inherit"
            variant="outlined"
            startIcon={<AddIcon />}
            onClick={handleAddRule}
            sx={{ mr: 1 }}
          >
            Add Rule
          </Button>
          <Button
            color="inherit"
            component={Link}
            to="/docs"
            startIcon={<MenuBookIcon />}
          >
            Docs
          </Button>
        </Toolbar>
      </AppBar>

      <Container maxWidth="xl" sx={{ mt: 3, mb: 3 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
          <Tabs value={selectedTab} onChange={handleTabChange}>
            <Tab label="All Rules" />
            <Tab label="Executables" />
            <Tab label="Scripts" />
            <Tab label="DLLs" />
            <Tab label="Windows Installer" />
            <Tab label="Packaged Apps" />
          </Tabs>
        </Box>

        <RuleList
          rules={filteredRules || []}
          onEdit={handleEditRule}
          onDelete={loadRules}
        />

        <RuleForm
          open={openForm}
          onClose={handleFormClose}
          rule={editingRule}
          onSave={loadRules}
        />
      </Container>

      <Dialog
        open={openImportDialog}
        onClose={() => setOpenImportDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Import XML from Text</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="XML Content"
            fullWidth
            multiline
            rows={15}
            variant="outlined"
            value={importXmlText}
            onChange={(e) => setImportXmlText(e.target.value)}
            placeholder="Paste your AppLocker XML policy here..."
            sx={{ mt: 2 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setOpenImportDialog(false)
            setImportXmlText('')
          }}>
            Cancel
          </Button>
          <Button onClick={handleImportTextSubmit} variant="contained">
            Import
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={openExportDialog}
        onClose={() => setOpenExportDialog(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Export XML as Text</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="XML Content"
            fullWidth
            multiline
            rows={20}
            variant="outlined"
            value={exportXmlText}
            onChange={(e) => setExportXmlText(e.target.value)}
            sx={{ mt: 2 }}
            InputProps={{
              readOnly: false,
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ContentCopyIcon />}
            onClick={handleCopyExportText}
            variant="outlined"
          >
            Copy to Clipboard
          </Button>
          <Button onClick={() => {
            setOpenExportDialog(false)
            setExportXmlText('')
          }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleSnackbarClose}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
      <Dialog
        open={clearConfirmDialog.open}
        onClose={handleCancelClear}
      >
        <DialogTitle>Confirm Clear Rules</DialogTitle>
        <DialogContent>
          <Typography>
            {clearConfirmDialog.collection
              ? `Are you sure you want to delete all ${clearConfirmDialog.collection} rules? This action cannot be undone.`
              : 'Are you sure you want to delete all rules? This action cannot be undone.'}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelClear}>Cancel</Button>
          <Button onClick={handleConfirmClear} color="error" variant="contained">
            Clear Rules
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

function DocsPage() {
  const location = useLocation()
  
  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component={Link} to="/" sx={{ flexGrow: 1, textDecoration: 'none', color: 'inherit' }}>
            AppLocker Policy Creator
          </Typography>
          <Button
            color="inherit"
            component={Link}
            to="/"
            sx={{ mr: 1 }}
          >
            Policy Creator
          </Button>
          <Button
            color="inherit"
            component={Link}
            to="/docs"
            startIcon={<MenuBookIcon />}
            sx={{
              backgroundColor: location.pathname === '/docs' ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
            }}
          >
            Documentation
          </Button>
        </Toolbar>
      </AppBar>
      <Docs />
    </Box>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<PolicyCreator />} />
        <Route path="/docs" element={<DocsPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
