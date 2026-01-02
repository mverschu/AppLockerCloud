/**
 * Client-side rule storage service
 * Replaces the backend API with localStorage-based persistence
 */

const STORAGE_KEY = 'applocker_rules'
const ENFORCEMENT_MODES_KEY = 'applocker_enforcement_modes'
const POLICY_VERSION_KEY = 'applocker_policy_version'

/**
 * Normalize conditions list for duplicate comparison
 */
function normalizeConditionsForComparison(conditions) {
  if (!conditions || conditions.length === 0) {
    return []
  }
  
  // Sort conditions by type, then by key values for consistent comparison
  const normalized = conditions.map(cond => {
    const sortedItems = Object.entries(cond).sort()
    return sortedItems
  })
  
  // Sort the list of conditions
  return normalized.sort((a, b) => {
    const aStr = JSON.stringify(a)
    const bStr = JSON.stringify(b)
    return aStr.localeCompare(bStr)
  })
}

/**
 * Normalize exceptions list for duplicate comparison
 */
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

/**
 * Check if two rules are duplicates
 */
function isDuplicateRule(rule1, rule2) {
  // Normalize user_or_group_sid (None, empty string, or "S-1-1-0" for Everyone are treated as same)
  function normalizeSid(sid) {
    if (!sid || sid === 'S-1-1-0' || sid.trim() === '') {
      return null
    }
    return sid.trim()
  }
  
  const sid1 = normalizeSid(rule1.user_or_group_sid)
  const sid2 = normalizeSid(rule2.user_or_group_sid)
  
  // Compare basic properties
  if (rule1.collection !== rule2.collection) {
    return false
  }
  if (rule1.action !== rule2.action) {
    return false
  }
  if (sid1 !== sid2) {
    return false
  }
  
  // Compare conditions (normalized)
  const cond1 = normalizeConditionsForComparison(rule1.conditions || [])
  const cond2 = normalizeConditionsForComparison(rule2.conditions || [])
  if (JSON.stringify(cond1) !== JSON.stringify(cond2)) {
    return false
  }
  
  // Compare exceptions (normalized)
  const exc1 = normalizeExceptionsForComparison(rule1.exceptions || [])
  const exc2 = normalizeExceptionsForComparison(rule2.exceptions || [])
  if (JSON.stringify(exc1) !== JSON.stringify(exc2)) {
    return false
  }
  
  return true
}

/**
 * Find if a duplicate of the new rule already exists in the list
 */
function findDuplicateRule(newRule, existingRules) {
  for (const existingRule of existingRules) {
    if (isDuplicateRule(newRule, existingRule)) {
      return existingRule
    }
  }
  return null
}

/**
 * Get all rules from storage
 */
export function getRules(collection = null) {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    let rules = stored ? JSON.parse(stored) : []
    
    // Convert date strings back to Date objects if needed
    rules = rules.map(rule => ({
      ...rule,
      created_at: rule.created_at ? new Date(rule.created_at) : new Date(),
      updated_at: rule.updated_at ? new Date(rule.updated_at) : new Date(),
    }))
    
    if (collection) {
      return rules.filter(rule => rule.collection === collection)
    }
    
    return rules
  } catch (error) {
    console.error('Error loading rules from storage:', error)
    return []
  }
}

/**
 * Get a specific rule by ID
 */
export function getRule(ruleId) {
  const rules = getRules()
  return rules.find(r => r.id === ruleId) || null
}

/**
 * Save rules to storage
 */
function saveRules(rules) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(rules))
  } catch (error) {
    console.error('Error saving rules to storage:', error)
    throw error
  }
}

/**
 * Create a new rule
 */
export function createRule(ruleData) {
  const rules = getRules()
  
  const newRule = {
    id: generateId(),
    name: ruleData.name,
    description: ruleData.description || '',
    collection: ruleData.collection,
    action: ruleData.action,
    user_or_group_sid: ruleData.user_or_group_sid || null,
    conditions: ruleData.conditions || [],
    exceptions: ruleData.exceptions || [],
    created_at: new Date(),
    updated_at: new Date(),
  }
  
  // Check for duplicates
  const duplicate = findDuplicateRule(newRule, rules)
  if (duplicate) {
    // Return the existing rule instead of creating a duplicate
    return duplicate
  }
  
  rules.push(newRule)
  saveRules(rules)
  return newRule
}

/**
 * Update an existing rule
 */
export function updateRule(ruleId, ruleData) {
  const rules = getRules()
  const ruleIndex = rules.findIndex(r => r.id === ruleId)
  
  if (ruleIndex === -1) {
    throw new Error('Rule not found')
  }
  
  const existingRule = rules[ruleIndex]
  
  // Update fields if provided
  if (ruleData.name !== undefined) {
    existingRule.name = ruleData.name
  }
  if (ruleData.description !== undefined) {
    existingRule.description = ruleData.description
  }
  if (ruleData.collection !== undefined) {
    existingRule.collection = ruleData.collection
  }
  if (ruleData.action !== undefined) {
    existingRule.action = ruleData.action
  }
  if (ruleData.user_or_group_sid !== undefined) {
    existingRule.user_or_group_sid = ruleData.user_or_group_sid
  }
  if (ruleData.conditions !== undefined) {
    existingRule.conditions = ruleData.conditions
  }
  if (ruleData.exceptions !== undefined) {
    existingRule.exceptions = ruleData.exceptions
  }
  
  existingRule.updated_at = new Date()
  
  saveRules(rules)
  return existingRule
}

/**
 * Delete a rule
 */
export function deleteRule(ruleId) {
  const rules = getRules()
  const ruleIndex = rules.findIndex(r => r.id === ruleId)
  
  if (ruleIndex === -1) {
    throw new Error('Rule not found')
  }
  
  rules.splice(ruleIndex, 1)
  saveRules(rules)
}

/**
 * Delete all rules, optionally filtered by collection
 */
export function deleteAllRules(collection = null) {
  if (collection) {
    const rules = getRules()
    const filteredRules = rules.filter(r => r.collection !== collection)
    saveRules(filteredRules)
  } else {
    saveRules([])
  }
}

/**
 * Get enforcement modes
 */
export function getEnforcementModes() {
  try {
    const stored = localStorage.getItem(ENFORCEMENT_MODES_KEY)
    return stored ? JSON.parse(stored) : {}
  } catch (error) {
    console.error('Error loading enforcement modes:', error)
    return {}
  }
}

/**
 * Set enforcement modes
 */
export function setEnforcementModes(modes) {
  try {
    localStorage.setItem(ENFORCEMENT_MODES_KEY, JSON.stringify(modes))
  } catch (error) {
    console.error('Error saving enforcement modes:', error)
    throw error
  }
}

/**
 * Get policy version
 */
export function getPolicyVersion() {
  try {
    return localStorage.getItem(POLICY_VERSION_KEY) || '1'
  } catch (error) {
    console.error('Error loading policy version:', error)
    return '1'
  }
}

/**
 * Set policy version
 */
export function setPolicyVersion(version) {
  try {
    localStorage.setItem(POLICY_VERSION_KEY, version)
  } catch (error) {
    console.error('Error saving policy version:', error)
    throw error
  }
}

/**
 * Generate a unique ID
 */
function generateId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

