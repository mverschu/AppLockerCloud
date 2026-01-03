/**
 * Rule validation service
 * Validates rules for conflicts, errors, and logical inconsistencies
 */

/**
 * Normalize path for comparison
 */
function normalizePath(path) {
  if (!path) return ''
  // Convert to lowercase and normalize slashes
  return path.replace(/\\/g, '/').toLowerCase().trim()
}

/**
 * Expand environment variables in path
 */
function expandPath(path) {
  if (!path) return ''
  return path
    .replace(/%WINDIR%/gi, 'C:\\Windows')
    .replace(/%SYSTEM32%/gi, 'C:\\Windows\\System32')
    .replace(/%PROGRAMFILES%/gi, 'C:\\Program Files')
    .replace(/%PROGRAMFILES\(X86\)%/gi, 'C:\\Program Files (x86)')
    .replace(/%PROGRAMDATA%/gi, 'C:\\ProgramData')
    .replace(/%OSDRIVE%/gi, 'C:')
}

/**
 * Check if two paths overlap (one matches the other)
 */
function pathsOverlap(path1, path2) {
  if (!path1 || !path2) return false
  
  const expanded1 = expandPath(path1)
  const expanded2 = expandPath(path2)
  
  // Normalize paths
  const norm1 = normalizePath(expanded1)
  const norm2 = normalizePath(expanded2)
  
  // Exact match
  if (norm1 === norm2) return true
  
  // Remove wildcards for base comparison
  const base1 = norm1.replace(/\/\*$/, '').replace(/\*$/, '')
  const base2 = norm2.replace(/\/\*$/, '').replace(/\*$/, '')
  
  // Check if one path is within the other
  if (base1 && norm2.startsWith(base1 + '/')) return true
  if (base2 && norm1.startsWith(base2 + '/')) return true
  
  // Check if paths are the same base
  if (base1 === base2) return true
  
  return false
}

/**
 * Check if a path condition matches a path
 */
function pathConditionMatches(condition, testPath) {
  if (!condition || condition.type !== 'FilePathCondition') return false
  if (!condition.path) return false
  
  return pathsOverlap(condition.path, testPath)
}

/**
 * Check if a publisher condition matches (simplified - exact match for now)
 */
function publisherConditionMatches(condition, testPublisher) {
  if (!condition || condition.type !== 'FilePublisherCondition') return false
  if (!condition.publisher_name) return false
  
  // Exact match or wildcard
  return condition.publisher_name === '*' || 
         condition.publisher_name === testPublisher ||
         testPublisher.includes(condition.publisher_name)
}

/**
 * Check if a hash condition matches
 */
function hashConditionMatches(condition, testHash) {
  if (!condition || condition.type !== 'FileHashCondition') return false
  if (!condition.file_hash) return false
  
  const conditionHash = condition.file_hash.replace(/^0x/i, '').toUpperCase()
  const testHashNorm = testHash.replace(/^0x/i, '').toUpperCase()
  
  return conditionHash === testHashNorm
}

/**
 * Check if a condition matches a test case
 */
function conditionMatches(condition, testCase) {
  if (!condition || !testCase) return false
  
  switch (condition.type) {
    case 'FilePathCondition':
      return pathConditionMatches(condition, testCase.path)
    case 'FilePublisherCondition':
      return publisherConditionMatches(condition, testCase.publisher)
    case 'FileHashCondition':
      return hashConditionMatches(condition, testCase.hash)
    default:
      return false
  }
}

/**
 * Check if an exception matches a test case
 */
function exceptionMatches(exception, testCase) {
  return conditionMatches(exception, testCase)
}

/**
 * Check if a rule would allow/deny a test case
 */
function ruleMatches(rule, testCase) {
  if (!rule || !testCase) return false
  
  // Check collection type
  if (testCase.collection && rule.collection !== testCase.collection) {
    return false
  }
  
  // Check user/group SID
  const ruleSid = rule.user_or_group_sid || 'S-1-1-0' // Default to Everyone
  if (testCase.userSid && ruleSid !== testCase.userSid && ruleSid !== 'S-1-1-0') {
    return false
  }
  
  // Check if any condition matches
  const conditionsMatch = rule.conditions && rule.conditions.some(cond => 
    conditionMatches(cond, testCase)
  )
  
  if (!conditionsMatch) return false
  
  // Check if any exception would exclude this
  if (rule.exceptions && rule.exceptions.some(exc => exceptionMatches(exc, testCase))) {
    return false // Exception excludes this
  }
  
  return true
}

/**
 * Validate a single rule
 */
export function validateRule(rule, allRules = []) {
  const errors = []
  const warnings = []
  
  // Required fields
  if (!rule.name || rule.name.trim() === '') {
    errors.push({
      type: 'error',
      field: 'name',
      message: 'Rule name is required',
    })
  }
  
  if (!rule.collection) {
    errors.push({
      type: 'error',
      field: 'collection',
      message: 'Collection type is required',
    })
  }
  
  if (!rule.action) {
    errors.push({
      type: 'error',
      field: 'action',
      message: 'Action (Allow/Deny) is required',
    })
  }
  
  // Conditions validation
  if (!rule.conditions || rule.conditions.length === 0) {
    errors.push({
      type: 'error',
      field: 'conditions',
      message: 'At least one condition is required',
    })
  } else {
    rule.conditions.forEach((condition, index) => {
      if (!condition.type) {
        errors.push({
          type: 'error',
          field: `conditions[${index}]`,
          message: 'Condition type is required',
        })
      }
      
      if (condition.type === 'FilePathCondition' && !condition.path) {
        errors.push({
          type: 'error',
          field: `conditions[${index}].path`,
          message: 'Path is required for FilePathCondition',
        })
      }
      
      if (condition.type === 'FilePublisherCondition' && !condition.publisher_name) {
        errors.push({
          type: 'error',
          field: `conditions[${index}].publisher_name`,
          message: 'Publisher name is required for FilePublisherCondition',
        })
      }
      
      if (condition.type === 'FileHashCondition') {
        if (!condition.file_hash) {
          errors.push({
            type: 'error',
            field: `conditions[${index}].file_hash`,
            message: 'File hash is required for FileHashCondition',
          })
        }
        if (!condition.source_file_name) {
          errors.push({
            type: 'error',
            field: `conditions[${index}].source_file_name`,
            message: 'Source file name is required for FileHashCondition',
          })
        }
      }
    })
  }
  
  // Warnings
  if (rule.action === 'Allow' && rule.conditions) {
    const hasWildcard = rule.conditions.some(cond => 
      cond.type === 'FilePathCondition' && 
      (cond.path === '*' || cond.path === '*.*')
    )
    
    if (hasWildcard && rule.user_or_group_sid !== 'S-1-5-32-544') {
      warnings.push({
        type: 'warning',
        field: 'conditions',
        message: 'Wildcard allow rule should typically be restricted to Administrators (S-1-5-32-544)',
      })
    }
  }
  
  return { errors, warnings }
}

/**
 * Detect conflicts between rules
 */
export function detectConflicts(rules) {
  const conflicts = []
  
  // Group rules by collection
  const rulesByCollection = {}
  rules.forEach(rule => {
    if (!rulesByCollection[rule.collection]) {
      rulesByCollection[rule.collection] = []
    }
    rulesByCollection[rule.collection].push(rule)
  })
  
  // Check for conflicts within each collection
  Object.keys(rulesByCollection).forEach(collection => {
    const collectionRules = rulesByCollection[collection]
    
    // Check each pair of rules
    for (let i = 0; i < collectionRules.length; i++) {
      for (let j = i + 1; j < collectionRules.length; j++) {
        const rule1 = collectionRules[i]
        const rule2 = collectionRules[j]
        
        // Check if rules have opposite actions
        if (rule1.action !== rule2.action) {
          // Check if they might conflict (same user/group or one is Everyone)
          const sid1 = rule1.user_or_group_sid || 'S-1-1-0'
          const sid2 = rule2.user_or_group_sid || 'S-1-1-0'
          
          if (sid1 === sid2 || sid1 === 'S-1-1-0' || sid2 === 'S-1-1-0') {
            // Check if conditions overlap
            const overlap = checkRuleOverlap(rule1, rule2)
            if (overlap) {
              conflicts.push({
                type: 'conflict',
                severity: 'error',
                rule1: {
                  id: rule1.id,
                  name: rule1.name,
                  action: rule1.action,
                },
                rule2: {
                  id: rule2.id,
                  name: rule2.name,
                  action: rule2.action,
                },
                collection,
                message: `Conflicting rules: "${rule1.name}" (${rule1.action}) and "${rule2.name}" (${rule2.action}) may overlap`,
                details: overlap.details,
              })
            }
          }
        }
      }
    }
  })
  
  return conflicts
}

/**
 * Check if two rules overlap
 */
function checkRuleOverlap(rule1, rule2) {
  if (!rule1.conditions || !rule2.conditions) return null
  
  // Check if any condition from rule1 matches any condition from rule2
  for (const cond1 of rule1.conditions) {
    for (const cond2 of rule2.conditions) {
      if (cond1.type === 'FilePathCondition' && cond2.type === 'FilePathCondition') {
        if (pathsOverlap(cond1.path, cond2.path)) {
          return {
            matches: true,
            details: `Path overlap: "${cond1.path}" and "${cond2.path}"`,
          }
        }
      } else if (cond1.type === 'FilePublisherCondition' && cond2.type === 'FilePublisherCondition') {
        // Check publisher overlap (simplified)
        if (cond1.publisher_name === cond2.publisher_name || 
            cond1.publisher_name === '*' || 
            cond2.publisher_name === '*') {
          return {
            matches: true,
            details: `Publisher overlap: "${cond1.publisher_name}" and "${cond2.publisher_name}"`,
          }
        }
      } else if (cond1.type === 'FileHashCondition' && cond2.type === 'FileHashCondition') {
        if (cond1.file_hash === cond2.file_hash) {
          return {
            matches: true,
            details: `Hash match: "${cond1.file_hash.substring(0, 16)}..."`,
          }
        }
      }
    }
  }
  
  return null
}

/**
 * Validate all rules
 */
export function validateAllRules(rules) {
  const results = {
    valid: true,
    errors: [],
    warnings: [],
    conflicts: [],
    ruleValidations: [],
  }
  
  // Validate each rule individually
  rules.forEach(rule => {
    const validation = validateRule(rule, rules)
    results.ruleValidations.push({
      ruleId: rule.id,
      ruleName: rule.name,
      ...validation,
    })
    
    results.errors.push(...validation.errors.map(err => ({
      ...err,
      ruleId: rule.id,
      ruleName: rule.name,
    })))
    results.warnings.push(...validation.warnings.map(warn => ({
      ...warn,
      ruleId: rule.id,
      ruleName: rule.name,
    })))
  })
  
  // Detect conflicts
  results.conflicts = detectConflicts(rules)
  
  // Overall validity
  results.valid = results.errors.length === 0 && results.conflicts.length === 0
  
  return results
}

/**
 * Test a file path against the policy
 */
export function testPolicy(rules, testCase) {
  const results = {
    allowed: false,
    denied: false,
    matchingRules: [],
    reason: '',
  }
  
  // Filter rules by collection if specified
  let relevantRules = rules
  if (testCase.collection) {
    relevantRules = rules.filter(r => r.collection === testCase.collection)
  }
  
  // Check each rule
  for (const rule of relevantRules) {
    if (ruleMatches(rule, testCase)) {
      results.matchingRules.push({
        id: rule.id,
        name: rule.name,
        action: rule.action,
      })
      
      if (rule.action === 'Allow') {
        results.allowed = true
        results.reason = `Allowed by rule: ${rule.name}`
      } else if (rule.action === 'Deny') {
        results.denied = true
        results.reason = `Denied by rule: ${rule.name}`
        // Deny takes precedence
        break
      }
    }
  }
  
  // Default deny if no rule matches
  if (!results.allowed && !results.denied) {
    results.reason = 'No matching rule found (default deny)'
  }
  
  return results
}

/**
 * Simulate policy impact for a list of test cases
 */
export function simulatePolicy(rules, testCases) {
  return testCases.map(testCase => ({
    ...testCase,
    result: testPolicy(rules, testCase),
  }))
}

