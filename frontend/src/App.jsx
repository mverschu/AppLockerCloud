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
  InputAdornment,
  IconButton,
  Paper,
  useMediaQuery,
  useTheme,
  Divider,
  ListItemIcon,
  ListItemText,
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
  DarkMode as DarkModeIcon,
  LightMode as LightModeIcon,
  Security as SecurityIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
  VerifiedUser as VerifiedUserIcon,
  Folder as FolderIcon,
  Build as BuildIcon,
  Visibility as VisibilityIcon,
  Menu as MenuIcon,
  GitHub as GitHubIcon,
} from '@mui/icons-material'
import RuleList from './components/RuleList'
import RuleForm from './components/RuleForm'
import Docs from './components/Docs'
import PolicyHardening from './components/PolicyHardening'
import ValidationPanel from './components/ValidationPanel'
import { useThemeMode } from './theme/ThemeProvider'
import { getRules, exportXML, importXML, importDefaultRules, exportCollectionXML, deleteAllRules } from './services/api'
import { validateAllRules } from './services/ruleValidator'

function PolicyCreator() {
  const { mode, toggleColorMode } = useThemeMode()
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
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
  const [searchQuery, setSearchQuery] = useState('')
  const [validationDialogOpen, setValidationDialogOpen] = useState(false)
  const [validationBeforeExport, setValidationBeforeExport] = useState(true)
  const [fileMenuAnchor, setFileMenuAnchor] = useState(null)
  const [toolsMenuAnchor, setToolsMenuAnchor] = useState(null)
  const [mobileMenuAnchor, setMobileMenuAnchor] = useState(null)

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
      // Validate before export if enabled
      if (validationBeforeExport && rules.length > 0) {
        const validation = validateAllRules(rules)
        if (!validation.valid) {
          const hasErrors = validation.errors.length > 0 || validation.conflicts.length > 0
          const message = hasErrors
            ? `Policy has ${validation.errors.length} errors and ${validation.conflicts.length} conflicts. Export anyway?`
            : `Policy has ${validation.warnings.length} warnings. Export anyway?`
          
          if (!window.confirm(message + '\n\nClick OK to export anyway, or Cancel to review validation first.')) {
            setValidationDialogOpen(true)
            return
          }
        }
      }
      
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

  // Filter rules by search query
  const filterRulesBySearch = (rulesToFilter, query) => {
    if (!query || !query.trim()) return rulesToFilter
    
    const searchLower = query.toLowerCase().trim()
    
    return rulesToFilter.filter(rule => {
      if (!rule) return false
      
      // Search in name
      if (rule.name && rule.name.toLowerCase().includes(searchLower)) return true
      
      // Search in description
      if (rule.description && rule.description.toLowerCase().includes(searchLower)) return true
      
      // Search in collection
      if (rule.collection && rule.collection.toLowerCase().includes(searchLower)) return true
      
      // Search in action
      if (rule.action && rule.action.toLowerCase().includes(searchLower)) return true
      
      // Search in user/group SID
      if (rule.user_or_group_sid && rule.user_or_group_sid.toLowerCase().includes(searchLower)) return true
      
      // Search in conditions
      if (rule.conditions && Array.isArray(rule.conditions)) {
        for (const condition of rule.conditions) {
          if (!condition) continue
          
          // FilePathCondition
          if (condition.path && condition.path.toLowerCase().includes(searchLower)) return true
          
          // FilePublisherCondition
          if (condition.publisher_name && condition.publisher_name.toLowerCase().includes(searchLower)) return true
          if (condition.product_name && condition.product_name.toLowerCase().includes(searchLower)) return true
          if (condition.binary_name && condition.binary_name.toLowerCase().includes(searchLower)) return true
          
          // FileHashCondition
          if (condition.file_hash && condition.file_hash.toLowerCase().includes(searchLower)) return true
          if (condition.source_file_name && condition.source_file_name.toLowerCase().includes(searchLower)) return true
        }
      }
      
      // Search in exceptions
      if (rule.exceptions && Array.isArray(rule.exceptions)) {
        for (const exception of rule.exceptions) {
          if (!exception) continue
          
          // FilePathCondition exception
          if (exception.path && exception.path.toLowerCase().includes(searchLower)) return true
          
          // FilePublisherCondition exception
          if (exception.publisher_name && exception.publisher_name.toLowerCase().includes(searchLower)) return true
          if (exception.product_name && exception.product_name.toLowerCase().includes(searchLower)) return true
          if (exception.binary_name && exception.binary_name.toLowerCase().includes(searchLower)) return true
          
          // FileHashCondition exception
          if (exception.file_hash && exception.file_hash.toLowerCase().includes(searchLower)) return true
          if (exception.source_file_name && exception.source_file_name.toLowerCase().includes(searchLower)) return true
        }
      }
      
      return false
    })
  }

  const filteredRules = useMemo(() => {
    if (!rules || rules.length === 0) return []
    
    // First filter by collection tab
    let filtered = rules
    if (selectedTab !== 0) {
      const collectionMap = {
        1: 'Exe',
        2: 'Script',
        3: 'Dll',
        4: 'Msi',
        5: 'Appx',
      }
      const targetCollection = collectionMap[selectedTab]
      if (targetCollection) {
        filtered = rules.filter(rule => rule && rule.collection === targetCollection)
      } else {
        return []
      }
    }
    
    // Then filter by search query
    return filterRulesBySearch(filtered, searchQuery)
  }, [rules, selectedTab, searchQuery])

  const handleFileMenuOpen = (event) => {
    setFileMenuAnchor(event.currentTarget)
  }

  const handleFileMenuClose = () => {
    setFileMenuAnchor(null)
  }

  const handleToolsMenuOpen = (event) => {
    setToolsMenuAnchor(event.currentTarget)
  }

  const handleToolsMenuClose = () => {
    setToolsMenuAnchor(null)
  }

  const handleMobileMenuOpen = (event) => {
    setMobileMenuAnchor(event.currentTarget)
  }

  const handleMobileMenuClose = () => {
    setMobileMenuAnchor(null)
  }

  const collectionMap = {
    1: 'Exe',
    2: 'Script',
    3: 'Dll',
    4: 'Msi',
    5: 'Appx',
  }
  const currentCollection = selectedTab > 0 ? collectionMap[selectedTab] : null

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <AppBar position="static" sx={{ flexShrink: 0 }}>
        <Toolbar sx={{ flexWrap: { xs: 'wrap', md: 'nowrap' }, gap: { xs: 0.5, md: 1 } }}>
          <Typography 
            variant={isMobile ? "subtitle1" : "h6"} 
            component={Link} 
            to="/" 
            sx={{ 
              flexGrow: { xs: 1, md: 1 }, 
              textDecoration: 'none', 
              color: 'inherit',
              minWidth: { xs: 'auto', md: 'auto' }
            }}
          >
            {isMobile ? 'AppLocker' : 'AppLocker Policy Creator'}
          </Typography>
          
          <input
            accept=".xml"
            style={{ display: 'none' }}
            id="import-button-file"
            type="file"
            onChange={handleImport}
          />

          {/* Mobile Menu */}
          {isMobile && (
            <>
              <IconButton
                color="inherit"
                onClick={handleMobileMenuOpen}
                sx={{ ml: 'auto' }}
              >
                <MenuIcon />
              </IconButton>
              <Menu
                anchorEl={mobileMenuAnchor}
                open={Boolean(mobileMenuAnchor)}
                onClose={handleMobileMenuClose}
              >
                <MenuItem onClick={() => { handleMobileMenuClose(); handleAddRule(); }}>
                  <ListItemIcon><AddIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Add Rule</ListItemText>
                </MenuItem>
                <MenuItem onClick={() => { handleMobileMenuClose(); handleImportDefaults(); }}>
                  <ListItemIcon><CloudDownloadIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Default Rules</ListItemText>
                </MenuItem>
                <MenuItem 
                  onClick={() => { handleMobileMenuClose(); handleClearRules(selectedTab); }}
                  disabled={!filteredRules || filteredRules.length === 0}
                >
                  <ListItemIcon><DeleteIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>
                    {selectedTab === 0 ? 'Clear All' : `Clear ${currentCollection || 'Collection'}`}
                  </ListItemText>
                </MenuItem>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 1, color: 'text.secondary' }}>File</Typography>
                <label htmlFor="import-button-file">
                  <MenuItem component="span" onClick={handleMobileMenuClose}>
                    <ListItemIcon><UploadIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>Import from File</ListItemText>
                  </MenuItem>
                </label>
                <MenuItem onClick={() => { handleMobileMenuClose(); handleImportFromText(); }}>
                  <ListItemIcon><UploadIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Import from Text</ListItemText>
                </MenuItem>
                <MenuItem 
                  onClick={() => { handleMobileMenuClose(); handleExport(false, null); }}
                  disabled={rules.length === 0}
                >
                  <ListItemIcon><DownloadIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Export All as File</ListItemText>
                </MenuItem>
                <MenuItem 
                  onClick={() => { handleMobileMenuClose(); handleExport(true, null); }}
                  disabled={rules.length === 0}
                >
                  <ListItemIcon><ContentCopyIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Export All as Text</ListItemText>
                </MenuItem>
                <Divider />
                <Typography variant="caption" sx={{ px: 2, py: 1, color: 'text.secondary' }}>Tools</Typography>
                <MenuItem onClick={() => { handleMobileMenuClose(); setValidationDialogOpen(true); }}>
                  <ListItemIcon><VerifiedUserIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Validate Policy</ListItemText>
                </MenuItem>
                <MenuItem component={Link} to="/hardening" onClick={handleMobileMenuClose}>
                  <ListItemIcon><SecurityIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Policy Hardening</ListItemText>
                </MenuItem>
                <MenuItem component={Link} to="/docs" onClick={handleMobileMenuClose}>
                  <ListItemIcon><MenuBookIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Documentation</ListItemText>
                </MenuItem>
              </Menu>
            </>
          )}

          {/* Desktop Menu */}
          {!isMobile && (
            <>
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
                startIcon={<CloudDownloadIcon />}
                onClick={handleImportDefaults}
                sx={{ mr: 1 }}
              >
                Default Rules
              </Button>
              
              <Button
                color="inherit"
                startIcon={<DeleteIcon />}
                onClick={() => handleClearRules(selectedTab)}
                disabled={!filteredRules || filteredRules.length === 0}
                sx={{ mr: 1 }}
              >
                {selectedTab === 0 ? 'Clear All' : `Clear ${currentCollection || 'Collection'}`}
              </Button>
              
              <Button
                color="inherit"
                startIcon={<FolderIcon />}
                endIcon={<ArrowDropDownIcon />}
                onClick={handleFileMenuOpen}
                sx={{ mr: 1 }}
              >
                File
              </Button>
              <Menu
                anchorEl={fileMenuAnchor}
                open={Boolean(fileMenuAnchor)}
                onClose={handleFileMenuClose}
              >
                <label htmlFor="import-button-file">
                  <MenuItem component="span" onClick={handleFileMenuClose}>
                    <ListItemIcon><UploadIcon fontSize="small" /></ListItemIcon>
                    <ListItemText>Import from File</ListItemText>
                  </MenuItem>
                </label>
                <MenuItem onClick={() => { handleFileMenuClose(); handleImportFromText(); }}>
                  <ListItemIcon><UploadIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Import from Text</ListItemText>
                </MenuItem>
                <Divider />
                <MenuItem 
                  onClick={() => { handleFileMenuClose(); handleExport(false, null); }}
                  disabled={rules.length === 0}
                >
                  <ListItemIcon><DownloadIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Export All as File</ListItemText>
                </MenuItem>
                <MenuItem 
                  onClick={() => { handleFileMenuClose(); handleExport(true, null); }}
                  disabled={rules.length === 0}
                >
                  <ListItemIcon><ContentCopyIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Export All as Text</ListItemText>
                </MenuItem>
                {selectedTab > 0 && currentCollection && (
                  <>
                    <Divider />
                    <MenuItem 
                      onClick={() => { handleFileMenuClose(); handleExport(false, currentCollection); }}
                      disabled={rules.length === 0}
                    >
                      <ListItemIcon><DownloadIcon fontSize="small" /></ListItemIcon>
                      <ListItemText>Export {currentCollection} as File</ListItemText>
                    </MenuItem>
                    <MenuItem 
                      onClick={() => { handleFileMenuClose(); handleExport(true, currentCollection); }}
                      disabled={rules.length === 0}
                    >
                      <ListItemIcon><ContentCopyIcon fontSize="small" /></ListItemIcon>
                      <ListItemText>Export {currentCollection} as Text</ListItemText>
                    </MenuItem>
                  </>
                )}
              </Menu>

              <Button
                color="inherit"
                startIcon={<BuildIcon />}
                endIcon={<ArrowDropDownIcon />}
                onClick={handleToolsMenuOpen}
                sx={{ mr: 1 }}
              >
                Tools
              </Button>
              <Menu
                anchorEl={toolsMenuAnchor}
                open={Boolean(toolsMenuAnchor)}
                onClose={handleToolsMenuClose}
              >
                <MenuItem onClick={() => { handleToolsMenuClose(); setValidationDialogOpen(true); }}>
                  <ListItemIcon><VerifiedUserIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Validate Policy</ListItemText>
                </MenuItem>
                <MenuItem component={Link} to="/hardening" onClick={handleToolsMenuClose}>
                  <ListItemIcon><SecurityIcon fontSize="small" /></ListItemIcon>
                  <ListItemText>Policy Hardening</ListItemText>
                </MenuItem>
              </Menu>

              <Button
                color="inherit"
                component={Link}
                to="/docs"
                startIcon={<MenuBookIcon />}
                sx={{ mr: 1 }}
              >
                Docs
              </Button>
            </>
          )}
        </Toolbar>
      </AppBar>

      <Container 
        maxWidth="xl" 
        sx={{ 
          mt: { xs: 2, md: 3 }, 
          mb: { xs: 2, md: 3 }, 
          px: { xs: 1, md: 3 }, 
          flexGrow: 1,
          display: 'flex',
          flexDirection: 'column',
          minHeight: 0,
          overflow: 'hidden',
        }}
      >
        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: { xs: 2, md: 3 }, flexShrink: 0, width: '100%', overflow: 'visible' }}>
          <Tabs 
            value={selectedTab} 
            onChange={handleTabChange}
            variant={isMobile ? "scrollable" : "standard"}
            scrollButtons={isMobile ? "auto" : false}
            sx={{ width: '100%', minHeight: 48 }}
          >
            <Tab label={isMobile ? "All" : "All Rules"} />
            <Tab label={isMobile ? "Exe" : "Executables"} />
            <Tab label={isMobile ? "Script" : "Scripts"} />
            <Tab label={isMobile ? "DLL" : "DLLs"} />
            <Tab label={isMobile ? "MSI" : "Windows Installer"} />
            <Tab label={isMobile ? "Appx" : "Packaged Apps"} />
          </Tabs>
        </Box>

        <Box sx={{ flexGrow: 1, overflow: 'auto', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <Paper sx={{ p: 2, mb: 3, flexShrink: 0 }}>
            <TextField
              fullWidth
              placeholder="Search rules by name, description, collection, action, paths, publishers, hashes..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
                endAdornment: searchQuery ? (
                  <InputAdornment position="end">
                    <IconButton
                      size="small"
                      onClick={() => setSearchQuery('')}
                      edge="end"
                    >
                      <ClearIcon />
                    </IconButton>
                  </InputAdornment>
                ) : null,
              }}
              variant="outlined"
            />
            {searchQuery && (
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                Found {filteredRules.length} rule{filteredRules.length !== 1 ? 's' : ''} matching "{searchQuery}"
              </Typography>
            )}
          </Paper>

          <RuleList
            rules={filteredRules || []}
            onEdit={handleEditRule}
            onDelete={loadRules}
          />
        </Box>

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

      <Dialog
        open={validationDialogOpen}
        onClose={() => setValidationDialogOpen(false)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle>Policy Validation & Testing</DialogTitle>
        <DialogContent>
          <ValidationPanel
            rules={rules}
            onRuleClick={(ruleId) => {
              const rule = rules.find(r => r.id === ruleId)
              if (rule) {
                setValidationDialogOpen(false)
                handleEditRule(rule)
              }
            }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setValidationDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Footer */}
      <Box
        component="footer"
        sx={{
          mt: 'auto',
          py: 0.5,
          px: 1.5,
          borderTop: 1,
          borderColor: 'divider',
          bgcolor: mode === 'dark' ? 'background.paper' : 'grey.50',
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 1,
          flexShrink: 0,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            AppLockerCloud
          </Typography>
          <Box
            component="a"
            href="https://github.com/mverschu/AppLockerCloud"
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.25,
              color: 'text.secondary',
              textDecoration: 'none',
              '&:hover': {
                color: 'primary.main',
              },
            }}
          >
            <GitHubIcon sx={{ fontSize: '0.875rem' }} />
            <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>GitHub</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <IconButton
            size="small"
            onClick={toggleColorMode}
            title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            sx={{ color: 'text.secondary', padding: 0.5 }}
          >
            {mode === 'dark' ? <LightModeIcon sx={{ fontSize: '1rem' }} /> : <DarkModeIcon sx={{ fontSize: '1rem' }} />}
          </IconButton>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            {mode === 'dark' ? 'Light' : 'Dark'}
          </Typography>
        </Box>
      </Box>
    </Box>
  )
}

function DocsPage() {
  const location = useLocation()
  const { mode, toggleColorMode } = useThemeMode()
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar sx={{ flexWrap: { xs: 'wrap', md: 'nowrap' } }}>
          <Typography 
            variant={isMobile ? "subtitle1" : "h6"} 
            component={Link} 
            to="/" 
            sx={{ flexGrow: 1, textDecoration: 'none', color: 'inherit' }}
          >
            {isMobile ? 'AppLocker' : 'AppLocker Policy Creator'}
          </Typography>
          {!isMobile && (
            <>
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
                  mr: 1,
                }}
              >
                Documentation
              </Button>
              <Button
                color="inherit"
                component={Link}
                to="/hardening"
                startIcon={<SecurityIcon />}
                sx={{
                  backgroundColor: location.pathname === '/hardening' ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
                  mr: 1,
                }}
              >
                Hardening
              </Button>
            </>
          )}
        </Toolbar>
      </AppBar>
      <Docs />
      
      {/* Footer */}
      <Box
        component="footer"
        sx={{
          mt: 'auto',
          py: 0.5,
          px: 1.5,
          borderTop: 1,
          borderColor: 'divider',
          bgcolor: mode === 'dark' ? 'background.paper' : 'grey.50',
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 1,
          flexShrink: 0,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            AppLockerCloud
          </Typography>
          <Box
            component="a"
            href="https://github.com/mverschu/AppLockerCloud"
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.25,
              color: 'text.secondary',
              textDecoration: 'none',
              '&:hover': {
                color: 'primary.main',
              },
            }}
          >
            <GitHubIcon sx={{ fontSize: '0.875rem' }} />
            <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>GitHub</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <IconButton
            size="small"
            onClick={toggleColorMode}
            title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            sx={{ color: 'text.secondary', padding: 0.5 }}
          >
            {mode === 'dark' ? <LightModeIcon sx={{ fontSize: '1rem' }} /> : <DarkModeIcon sx={{ fontSize: '1rem' }} />}
          </IconButton>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            {mode === 'dark' ? 'Light' : 'Dark'}
          </Typography>
        </Box>
      </Box>
    </Box>
  )
}

function HardeningPage() {
  const location = useLocation()
  const { mode, toggleColorMode } = useThemeMode()
  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <AppBar position="static">
        <Toolbar sx={{ flexWrap: { xs: 'wrap', md: 'nowrap' } }}>
          <Typography 
            variant={isMobile ? "subtitle1" : "h6"} 
            component={Link} 
            to="/" 
            sx={{ flexGrow: 1, textDecoration: 'none', color: 'inherit' }}
          >
            {isMobile ? 'AppLocker' : 'AppLocker Policy Creator'}
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
            sx={{ mr: 1 }}
          >
            Documentation
          </Button>
          <Button
            color="inherit"
            component={Link}
            to="/hardening"
            startIcon={<SecurityIcon />}
            sx={{
              backgroundColor: location.pathname === '/hardening' ? 'rgba(255, 255, 255, 0.1)' : 'transparent',
              mr: 1,
            }}
          >
            Hardening
          </Button>
        </Toolbar>
      </AppBar>
      <PolicyHardening />
      
      {/* Footer */}
      <Box
        component="footer"
        sx={{
          mt: 'auto',
          py: 0.5,
          px: 1.5,
          borderTop: 1,
          borderColor: 'divider',
          bgcolor: mode === 'dark' ? 'background.paper' : 'grey.50',
          display: 'flex',
          flexDirection: { xs: 'column', sm: 'row' },
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 1,
          flexShrink: 0,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            AppLockerCloud
          </Typography>
          <Box
            component="a"
            href="https://github.com/mverschu/AppLockerCloud"
            target="_blank"
            rel="noopener noreferrer"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.25,
              color: 'text.secondary',
              textDecoration: 'none',
              '&:hover': {
                color: 'primary.main',
              },
            }}
          >
            <GitHubIcon sx={{ fontSize: '0.875rem' }} />
            <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>GitHub</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <IconButton
            size="small"
            onClick={toggleColorMode}
            title={mode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            sx={{ color: 'text.secondary', padding: 0.5 }}
          >
            {mode === 'dark' ? <LightModeIcon sx={{ fontSize: '1rem' }} /> : <DarkModeIcon sx={{ fontSize: '1rem' }} />}
          </IconButton>
          <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.7rem' }}>
            {mode === 'dark' ? 'Light' : 'Dark'}
          </Typography>
        </Box>
      </Box>
    </Box>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<PolicyCreator />} />
        <Route path="/docs" element={<DocsPage />} />
        <Route path="/hardening" element={<HardeningPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
