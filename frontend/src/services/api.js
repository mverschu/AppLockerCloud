/**
 * Client-side API service
 * Replaces HTTP calls with client-side storage and XML operations
 */
import * as storage from './storage'
import { generatePolicy, parseXML, exportCollection } from './xmlGenerator'
import defaultRulesXML from '../assets/default_rules.xml?raw'

export const getRules = async (collection = null) => {
  return storage.getRules(collection)
}

export const getRule = async (id) => {
  return storage.getRule(id)
}

export const createRule = async (ruleData) => {
  return storage.createRule(ruleData)
}

export const updateRule = async (id, ruleData) => {
  return storage.updateRule(id, ruleData)
}

export const deleteRule = async (id) => {
  storage.deleteRule(id)
}

export const exportXML = async (rules) => {
  const enforcementModes = storage.getEnforcementModes()
  const version = storage.getPolicyVersion()
  
  // Convert enforcement modes format if needed
  const modes = {}
  for (const [key, value] of Object.entries(enforcementModes)) {
    modes[key] = value
  }
  
  return generatePolicy(rules, modes, version)
}

export const exportCollectionXML = async (collectionType) => {
  const rules = storage.getRules(collectionType)
  const enforcementModes = storage.getEnforcementModes()
  const enforcementMode = enforcementModes[collectionType] || 'AuditOnly'
  
  return exportCollection(collectionType, rules, enforcementMode)
}

export const importXML = async (xmlContent) => {
  try {
    const { rules: importedRules, enforcementModes, version } = parseXML(xmlContent)
    
    if (!importedRules || importedRules.length === 0) {
      throw new Error('No rules found in XML file')
    }
    
    // Store enforcement modes and version
    const modes = {}
    for (const [key, value] of Object.entries(enforcementModes)) {
      modes[key] = value
    }
    storage.setEnforcementModes(modes)
    storage.setPolicyVersion(version)
    
    // Validate and add imported rules to store with new IDs
    const validatedRules = []
    let skippedDuplicates = 0
    
    for (let i = 0; i < importedRules.length; i++) {
      const rule = importedRules[i]
      try {
        // Ensure rule has required fields
        if (!rule.id) {
          rule.id = generateId()
        }
        rule.created_at = new Date()
        rule.updated_at = new Date()
        
        // Check for duplicates before adding
        const existingRules = storage.getRules()
        const duplicate = findDuplicateRule(rule, existingRules)
        if (duplicate) {
          skippedDuplicates++
          continue // Skip duplicate, keep existing one
        }
        
        validatedRules.push(rule)
        storage.createRule(rule)
      } catch (ruleError) {
        // Skip invalid rules but continue processing
        console.warn(`Error processing rule ${i + 1} (${rule.name || 'unknown'}):`, ruleError)
        continue
      }
    }
    
    if (validatedRules.length === 0 && skippedDuplicates === 0) {
      throw new Error('No valid rules could be imported from XML')
    }
    
    const message = `Successfully imported ${validatedRules.length} rules` +
      (skippedDuplicates > 0 ? ` (${skippedDuplicates} duplicates skipped)` : '')
    
    return {
      message,
      rules: validatedRules,
      enforcement_modes: modes,
      version,
    }
  } catch (error) {
    throw new Error(`Failed to import XML: ${error.message}`)
  }
}

export const getCollections = async () => {
  return {
    collections: [
      {
        value: 'Exe',
        label: 'Executable Rules',
        description: 'Controls execution of .exe and .com files',
        file_types: ['.exe', '.com'],
      },
      {
        value: 'Script',
        label: 'Script Rules',
        description: 'Controls execution of scripts (.ps1, .bat, .cmd, .vbs, .js)',
        file_types: ['.ps1', '.bat', '.cmd', '.vbs', '.js'],
      },
      {
        value: 'Dll',
        label: 'DLL Rules',
        description: 'Controls loading of DLL and OCX files',
        file_types: ['.dll', '.ocx'],
      },
      {
        value: 'Msi',
        label: 'Windows Installer Rules',
        description: 'Controls installation of .msi, .msp, .mst files',
        file_types: ['.msi', '.msp', '.mst'],
      },
      {
        value: 'Appx',
        label: 'Packaged App Rules',
        description: 'Controls UWP/MSIX packaged applications',
        file_types: ['UWP/MSIX apps'],
      },
    ],
  }
}

export const getDefaultRules = async () => {
  return {
    default_rules: [
      {
        name: 'Allow Windows and Program Files (Executables)',
        description: 'Default rule to allow executables from Windows and Program Files directories',
        collection: 'Exe',
        action: 'Allow',
        conditions: [
          {
            type: 'FilePathCondition',
            path: '%WINDIR%\\*',
          },
          {
            type: 'FilePathCondition',
            path: '%PROGRAMFILES%\\*',
          },
        ],
      },
      {
        name: 'Allow Windows and Program Files (Scripts)',
        description: 'Default rule to allow scripts from Windows and Program Files directories',
        collection: 'Script',
        action: 'Allow',
        conditions: [
          {
            type: 'FilePathCondition',
            path: '%WINDIR%\\*',
          },
          {
            type: 'FilePathCondition',
            path: '%PROGRAMFILES%\\*',
          },
        ],
      },
      {
        name: 'Allow Administrators (All)',
        description: 'Allow all files for administrators',
        collection: 'Exe',
        action: 'Allow',
        user_or_group_sid: 'S-1-5-32-544', // Administrators group
        conditions: [
          {
            type: 'FilePathCondition',
            path: '*',
          },
        ],
      },
    ],
  }
}

export const importDefaultRules = async (collectionType = null) => {
  try {
    // Load default rules XML
    const { rules: importedRules, enforcementModes, version } = parseXML(defaultRulesXML)
    
    // Filter by collection type if specified
    let filteredRules = importedRules
    if (collectionType) {
      filteredRules = importedRules.filter(r => r.collection === collectionType)
      
      // Store enforcement mode for this collection
      if (enforcementModes[collectionType]) {
        const modes = storage.getEnforcementModes()
        modes[collectionType] = enforcementModes[collectionType]
        storage.setEnforcementModes(modes)
      }
    } else {
      // Store all enforcement modes
      storage.setEnforcementModes(enforcementModes)
      storage.setPolicyVersion(version)
    }
    
    if (filteredRules.length === 0) {
      throw new Error('No default rules found for the specified collection')
    }
    
    // Add imported rules to store with new IDs
    const validatedRules = []
    let skippedDuplicates = 0
    
    for (let i = 0; i < filteredRules.length; i++) {
      const rule = filteredRules[i]
      try {
        // Ensure rule has required fields
        if (!rule.id) {
          rule.id = generateId()
        }
        rule.created_at = new Date()
        rule.updated_at = new Date()
        
        // Check for duplicates before adding
        const existingRules = storage.getRules()
        const duplicate = findDuplicateRule(rule, existingRules)
        if (duplicate) {
          skippedDuplicates++
          continue // Skip duplicate, keep existing one
        }
        
        validatedRules.push(rule)
        storage.createRule(rule)
      } catch (ruleError) {
        // Skip invalid rules but continue processing
        console.warn(`Error processing rule ${i + 1} (${rule.name || 'unknown'}):`, ruleError)
        continue
      }
    }
    
    if (validatedRules.length === 0 && skippedDuplicates === 0) {
      throw new Error('No valid default rules could be imported')
    }
    
    const message = `Successfully imported ${validatedRules.length} default rules` +
      (skippedDuplicates > 0 ? ` (${skippedDuplicates} duplicates skipped)` : '')
    
    return {
      message,
      rules: validatedRules,
    }
  } catch (error) {
    throw new Error(`Failed to import default rules: ${error.message}`)
  }
}

export const deleteAllRules = async (collectionType = null) => {
  storage.deleteAllRules(collectionType)
}

// Helper functions for duplicate detection
function normalizeConditionsForComparison(conditions) {
  if (!conditions || conditions.length === 0) {
    return []
  }
  
  const normalized = conditions.map(cond => {
    const sortedItems = Object.entries(cond).sort()
    return sortedItems
  })
  
  return normalized.sort((a, b) => {
    const aStr = JSON.stringify(a)
    const bStr = JSON.stringify(b)
    return aStr.localeCompare(bStr)
  })
}

function normalizeExceptionsForComparison(exceptions) {
  if (!exceptions || exceptions.length === 0) {
    return []
  }
  
  const normalized = exceptions.map(exc => {
    const sortedItems = Object.entries(exc).sort()
    return sortedItems
  })
  
  return normalized.sort((a, b) => {
    const aStr = JSON.stringify(a)
    const bStr = JSON.stringify(b)
    return aStr.localeCompare(bStr)
  })
}

function isDuplicateRule(rule1, rule2) {
  function normalizeSid(sid) {
    if (!sid || sid === 'S-1-1-0' || sid.trim() === '') {
      return null
    }
    return sid.trim()
  }
  
  const sid1 = normalizeSid(rule1.user_or_group_sid)
  const sid2 = normalizeSid(rule2.user_or_group_sid)
  
  if (rule1.collection !== rule2.collection) return false
  if (rule1.action !== rule2.action) return false
  if (sid1 !== sid2) return false
  
  const cond1 = normalizeConditionsForComparison(rule1.conditions || [])
  const cond2 = normalizeConditionsForComparison(rule2.conditions || [])
  if (JSON.stringify(cond1) !== JSON.stringify(cond2)) return false
  
  const exc1 = normalizeExceptionsForComparison(rule1.exceptions || [])
  const exc2 = normalizeExceptionsForComparison(rule2.exceptions || [])
  if (JSON.stringify(exc1) !== JSON.stringify(exc2)) return false
  
  return true
}

function findDuplicateRule(newRule, existingRules) {
  for (const existingRule of existingRules) {
    if (isDuplicateRule(newRule, existingRule)) {
      return existingRule
    }
  }
  return null
}

function generateId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

