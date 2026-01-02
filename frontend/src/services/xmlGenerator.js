/**
 * Client-side AppLocker XML Generator and Parser
 * Replaces the Python lxml-based XML generation/parsing
 */

/**
 * Generate a complete AppLocker XML policy
 */
export function generatePolicy(rules, enforcementModes = {}, version = '1') {
  const doc = document.implementation.createDocument(null, null, null)
  const root = doc.createElement('AppLockerPolicy')
  root.setAttribute('Version', version)
  doc.appendChild(root)

  // Group rules by collection type
  const rulesByCollection = {
    Exe: [],
    Script: [],
    Dll: [],
    Msi: [],
    Appx: [],
  }

  for (const rule of rules) {
    if (rulesByCollection[rule.collection]) {
      rulesByCollection[rule.collection].push(rule)
    }
  }

  // Default enforcement mode
  const defaultEnforcement = enforcementModes[null] || enforcementModes[''] || 'AuditOnly'

  // Create collection elements for each type that has rules
  for (const [collectionType, collectionRules] of Object.entries(rulesByCollection)) {
    if (collectionRules.length > 0) {
      const collectionEnforcement = enforcementModes[collectionType] || defaultEnforcement
      const collectionElem = createCollection(collectionType, collectionRules, collectionEnforcement, doc)
      root.appendChild(collectionElem)
    }
  }

  // Convert to XML string
  const serializer = new XMLSerializer()
  return serializer.serializeToString(doc)
}

/**
 * Create a rule collection element
 */
function createCollection(collectionType, rules, enforcementMode, doc) {
  const collectionElem = doc.createElement('RuleCollection')
  collectionElem.setAttribute('Type', collectionType)
  collectionElem.setAttribute('EnforcementMode', enforcementMode)

  // Preserve original order of rules
  for (const rule of rules) {
    const ruleElem = createRule(rule, doc)
    collectionElem.appendChild(ruleElem)
  }

  return collectionElem
}

/**
 * Create a rule element
 */
function createRule(rule, doc) {
  const ruleId = rule.id || generateRuleId()
  
  // Determine rule element type based on conditions
  const ruleType = determineRuleType(rule.conditions)
  
  // Set user or group (default to Everyone SID)
  const userSid = rule.user_or_group_sid || 'S-1-1-0'
  
  // Create rule element with attributes
  const ruleElem = doc.createElement(ruleType)
  ruleElem.setAttribute('Id', ruleId)
  ruleElem.setAttribute('Name', rule.name)
  ruleElem.setAttribute('Description', rule.description || '')
  ruleElem.setAttribute('UserOrGroupSid', userSid)
  ruleElem.setAttribute('Action', rule.action)
  
  // Add conditions
  const conditionsElem = doc.createElement('Conditions')
  
  // For FileHashRule, group all FileHashCondition entries into a single FileHashCondition
  if (ruleType === 'FileHashRule') {
    const hashConditions = rule.conditions.filter(cond => cond.type === 'FileHashCondition')
    if (hashConditions.length > 0) {
      const hashElem = doc.createElement('FileHashCondition')
      for (const condition of hashConditions) {
        const fileHash = doc.createElement('FileHash')
        fileHash.setAttribute('Type', condition.hash_type || 'SHA256')
        
        // Add 0x prefix to hash data to match original format
        let hashData = condition.file_hash || ''
        if (hashData && !hashData.startsWith('0x') && !hashData.startsWith('0X')) {
          hashData = '0x' + hashData.toUpperCase()
        }
        
        fileHash.setAttribute('Data', hashData)
        fileHash.setAttribute('SourceFileName', condition.source_file_name || '')
        
        if (condition.source_file_length) {
          fileHash.setAttribute('SourceFileLength', String(condition.source_file_length))
        }
        
        hashElem.appendChild(fileHash)
      }
      conditionsElem.appendChild(hashElem)
    }
  } else {
    // For other rule types, create condition elements normally
    for (const condition of rule.conditions) {
      const conditionElem = createCondition(condition, doc)
      conditionsElem.appendChild(conditionElem)
    }
  }
  
  ruleElem.appendChild(conditionsElem)
  
  // Add exceptions if present (for FilePathRule)
  if (rule.exceptions && rule.exceptions.length > 0) {
    const exceptionsElem = doc.createElement('Exceptions')
    for (const exception of rule.exceptions) {
      if (exception.type === 'FilePathCondition') {
        const excElem = doc.createElement('FilePathCondition')
        excElem.setAttribute('Path', exception.path || '')
        exceptionsElem.appendChild(excElem)
      } else if (exception.type === 'FilePublisherCondition') {
        const excElem = doc.createElement('FilePublisherCondition')
        excElem.setAttribute('PublisherName', exception.publisher_name || '*')
        excElem.setAttribute('ProductName', exception.product_name || '*')
        excElem.setAttribute('BinaryName', exception.binary_name || '*')
        
        // Add BinaryVersionRange if version is specified
        let lowSection = '*'
        let highSection = '*'
        
        // Handle version_range_type if present (new format)
        if (exception.version_range_type) {
          if (exception.version_range_type === 'and_above' && exception.version_value) {
            lowSection = exception.version_value
            highSection = '*'
          } else if (exception.version_range_type === 'and_below' && exception.version_value) {
            lowSection = '*'
            highSection = exception.version_value
          } else if (exception.version_range_type === 'exactly' && exception.version_value) {
            lowSection = exception.version_value
            highSection = exception.version_value
          }
          // If version_range_type is 'any' or not recognized, leave as */*
        } else if (exception.version && exception.version !== '*') {
          // Legacy format: parse version string
          if (exception.version.includes('-')) {
            const [low, high] = exception.version.split('-')
            lowSection = low || '*'
            highSection = high || '*'
          } else {
            lowSection = exception.version
            highSection = exception.version
          }
        }
        
        if (lowSection !== '*' || highSection !== '*') {
          const versionRange = doc.createElement('BinaryVersionRange')
          versionRange.setAttribute('LowSection', lowSection)
          versionRange.setAttribute('HighSection', highSection)
          excElem.appendChild(versionRange)
        }
        
        exceptionsElem.appendChild(excElem)
      } else if (exception.type === 'FileHashCondition') {
        const excElem = doc.createElement('FileHashCondition')
        const fileHash = doc.createElement('FileHash')
        fileHash.setAttribute('Type', exception.hash_type || 'SHA256')
        
        // Add 0x prefix to hash data if not present
        let hashData = exception.file_hash || ''
        if (hashData && !hashData.startsWith('0x') && !hashData.startsWith('0X')) {
          hashData = '0x' + hashData.toUpperCase()
        }
        
        fileHash.setAttribute('Data', hashData)
        fileHash.setAttribute('SourceFileName', exception.source_file_name || '')
        
        if (exception.source_file_length) {
          fileHash.setAttribute('SourceFileLength', String(exception.source_file_length))
        }
        
        excElem.appendChild(fileHash)
        exceptionsElem.appendChild(excElem)
      }
    }
    ruleElem.appendChild(exceptionsElem)
  }
  
  return ruleElem
}

/**
 * Determine the XML rule element type based on conditions
 */
function determineRuleType(conditions) {
  if (!conditions || conditions.length === 0) {
    return 'FilePathRule'
  }
  
  const conditionTypes = conditions.map(cond => cond.type || '')
  
  // If all conditions are hash conditions, use FileHashRule
  if (conditionTypes.every(ct => ct === 'FileHashCondition')) {
    return 'FileHashRule'
  }
  
  // If all conditions are publisher conditions, use FilePublisherRule
  if (conditionTypes.every(ct => ct === 'FilePublisherCondition')) {
    return 'FilePublisherRule'
  }
  
  // Otherwise, use FilePathRule (default)
  return 'FilePathRule'
}

/**
 * Create a condition element based on condition type
 */
function createCondition(condition, doc) {
  const conditionType = condition.type || ''
  
  if (conditionType === 'FilePathCondition' || (!conditionType && condition.path)) {
    return createPathCondition(condition, doc)
  } else if (conditionType === 'FilePublisherCondition' || (!conditionType && condition.publisher_name)) {
    return createPublisherCondition(condition, doc)
  } else if (conditionType === 'FileHashCondition' || (!conditionType && condition.file_hash)) {
    return createHashCondition(condition, doc)
  } else {
    // Default to path condition if type is unclear
    if (condition.path) {
      return createPathCondition(condition, doc)
    }
    throw new Error(`Unknown condition type: ${conditionType || 'unknown'}`)
  }
}

/**
 * Create a file path condition
 */
function createPathCondition(condition, doc) {
  const pathElem = doc.createElement('FilePathCondition')
  pathElem.setAttribute('Path', condition.path || '')
  return pathElem
}

/**
 * Create a file publisher condition
 */
function createPublisherCondition(condition, doc) {
  const pubName = condition.publisher_name || '*'
  const productName = condition.product_name || '*'
  const binaryName = condition.binary_name || '*'
  
  const pubElem = doc.createElement('FilePublisherCondition')
  pubElem.setAttribute('PublisherName', String(pubName))
  pubElem.setAttribute('ProductName', String(productName))
  pubElem.setAttribute('BinaryName', String(binaryName))
  
  // Binary version range
  let version = condition.version || '*'
  let lowSection = '*'
  let highSection = '*'
  
  // Handle version_range_type if present (new format)
  if (condition.version_range_type) {
    if (condition.version_range_type === 'and_above' && condition.version_value) {
      lowSection = condition.version_value
      highSection = '*'
    } else if (condition.version_range_type === 'and_below' && condition.version_value) {
      lowSection = '*'
      highSection = condition.version_value
    } else if (condition.version_range_type === 'exactly' && condition.version_value) {
      lowSection = condition.version_value
      highSection = condition.version_value
    }
    // If version_range_type is 'any' or not recognized, leave as */*
  } else {
    // Legacy format: try to detect type from version string
    if (typeof version === 'string' && version.includes('-')) {
      const parts = version.split('-', 2)
      const low = parts[0] || '*'
      const high = parts[1] || '*'
      // Try to detect the type
      if (low !== '*' && high === '*') {
        lowSection = low
        highSection = '*'
      } else if (low === '*' && high !== '*') {
        lowSection = '*'
        highSection = high
      } else if (low === high && low !== '*') {
        lowSection = low
        highSection = low
      } else {
        // Unknown format, default to any
        lowSection = '*'
        highSection = '*'
      }
    } else if (version !== '*') {
      // Single version - treat as exactly
      lowSection = version
      highSection = version
    }
  }
  
  const binaryVersionRange = doc.createElement('BinaryVersionRange')
  binaryVersionRange.setAttribute('LowSection', lowSection)
  binaryVersionRange.setAttribute('HighSection', highSection)
  pubElem.appendChild(binaryVersionRange)
  
  return pubElem
}

/**
 * Create a file hash condition
 */
function createHashCondition(condition, doc) {
  const hashElem = doc.createElement('FileHashCondition')
  
  // Check if this condition has multiple hashes
  const hashes = condition.hashes || []
  
  // If no hashes array, create one from the single hash fields (backward compatibility)
  const hashList = hashes.length > 0 ? hashes : [{
    file_hash: condition.file_hash || '',
    hash_type: condition.hash_type || 'SHA256',
    source_file_name: condition.source_file_name || '',
    source_file_length: condition.source_file_length,
  }]
  
  // Create a FileHash element for each hash
  for (const hashItem of hashList) {
    const fileHash = doc.createElement('FileHash')
    fileHash.setAttribute('Type', hashItem.hash_type || 'SHA256')
    
    // Add 0x prefix to hash data to match original format
    let hashData = hashItem.file_hash || ''
    if (hashData && !hashData.startsWith('0x') && !hashData.startsWith('0X')) {
      hashData = '0x' + hashData.toUpperCase()
    }
    
    fileHash.setAttribute('Data', hashData)
    fileHash.setAttribute('SourceFileName', hashItem.source_file_name || '')
    
    if (hashItem.source_file_length) {
      fileHash.setAttribute('SourceFileLength', String(hashItem.source_file_length))
    }
    
    hashElem.appendChild(fileHash)
  }
  
  return hashElem
}

/**
 * Generate a unique rule ID
 */
function generateRuleId() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

/**
 * Parse an existing AppLocker XML policy into Rule objects
 */
export function parseXML(xmlString) {
  const parser = new DOMParser()
  const doc = parser.parseFromString(xmlString, 'text/xml')
  
  // Check for parsing errors
  const parserError = doc.querySelector('parsererror')
  if (parserError) {
    throw new Error(`XML parsing error: ${parserError.textContent}`)
  }
  
  const root = doc.documentElement
  const rules = []
  const enforcementModes = {}
  let version = '1'
  
  // Check if root is AppLockerPolicy or RuleCollection
  let collections = []
  if (root.tagName === 'AppLockerPolicy' || root.tagName.endsWith(':AppLockerPolicy')) {
    version = root.getAttribute('Version') || '1'
    collections = Array.from(root.getElementsByTagName('RuleCollection'))
  } else if (root.tagName === 'RuleCollection' || root.tagName.endsWith(':RuleCollection')) {
    collections = [root]
  } else {
    throw new Error(`Unexpected root element: ${root.tagName}`)
  }
  
  for (const collection of collections) {
    const collectionTypeStr = collection.getAttribute('Type') || ''
    const collectionType = mapCollectionType(collectionTypeStr)
    
    // Store enforcement mode for this collection
    const enforcementMode = collection.getAttribute('EnforcementMode') || 'AuditOnly'
    enforcementModes[collectionType] = enforcementMode
    
    // Find all rule types in document order
    const ruleElements = []
    for (const child of Array.from(collection.children)) {
      const tag = child.tagName
      if (tag === 'FilePathRule' || tag === 'FileHashRule' || tag === 'FilePublisherRule' ||
          tag.endsWith(':FilePathRule') || tag.endsWith(':FileHashRule') || tag.endsWith(':FilePublisherRule')) {
        ruleElements.push(child)
      }
    }
    
    // Fallback: if no rules found by iterating, try getElementsByTagName
    if (ruleElements.length === 0) {
      ruleElements.push(
        ...Array.from(collection.getElementsByTagName('FilePathRule')),
        ...Array.from(collection.getElementsByTagName('FileHashRule')),
        ...Array.from(collection.getElementsByTagName('FilePublisherRule'))
      )
    }
    
    for (const ruleElem of ruleElements) {
      const rule = parseRuleElement(ruleElem, collectionType)
      rules.push(rule)
    }
  }
  
  return { rules, enforcementModes, version }
}

/**
 * Map XML collection type string to RuleCollection enum value
 */
function mapCollectionType(typeStr) {
  const mapping = {
    'Exe': 'Exe',
    'Script': 'Script',
    'Dll': 'Dll',
    'Msi': 'Msi',
    'Appx': 'Appx',
  }
  return mapping[typeStr] || 'Exe'
}

/**
 * Parse a rule element into a Rule object
 */
function parseRuleElement(ruleElem, collectionType) {
  const ruleId = ruleElem.getAttribute('Id') || ''
  const name = ruleElem.getAttribute('Name') || ''
  const description = ruleElem.getAttribute('Description') || ''
  
  // Parse user or group SID
  let userSid = ruleElem.getAttribute('UserOrGroupSid')
  if (!userSid) {
    const userSidElem = ruleElem.querySelector('UserOrGroupSid')
    userSid = userSidElem ? userSidElem.textContent : 'S-1-1-0'
  }
  
  // Parse action
  let actionStr = ruleElem.getAttribute('Action')
  if (!actionStr) {
    const actionElem = ruleElem.querySelector('Action')
    actionStr = actionElem ? actionElem.textContent : 'Allow'
  }
  const action = actionStr === 'Allow' ? 'Allow' : 'Deny'
  
  // Parse conditions
  const conditions = []
  const conditionsElem = ruleElem.querySelector('Conditions') || ruleElem
  
  // Path conditions
  const pathConditions = conditionsElem.querySelectorAll('FilePathCondition')
  for (const pathCond of pathConditions) {
    conditions.push({
      type: 'FilePathCondition',
      path: pathCond.getAttribute('Path') || '',
    })
  }
  
  // Publisher conditions
  const pubConditions = conditionsElem.querySelectorAll('FilePublisherCondition')
  for (const pubCond of pubConditions) {
    const pubName = pubCond.getAttribute('PublisherName') || '*'
    
    const productElem = pubCond.querySelector('ProductName')
    const binaryElem = pubCond.querySelector('BinaryName')
    const versionElem = pubCond.querySelector('BinaryVersionRange')
    
    const productName = productElem ? productElem.textContent : (pubCond.getAttribute('ProductName') || '*')
    const binaryName = binaryElem ? binaryElem.textContent : (pubCond.getAttribute('BinaryName') || '*')
    
    const condition = {
      type: 'FilePublisherCondition',
      publisher_name: pubName,
      product_name: productName,
      binary_name: binaryName,
    }
    
    if (versionElem) {
      const lowSection = versionElem.getAttribute('LowSection') || '*'
      const highSection = versionElem.getAttribute('HighSection') || '*'
      
      // Detect version range type
      if (lowSection === '*' && highSection === '*') {
        condition.version_range_type = 'any'
        condition.version = '*'
        condition.version_value = ''
      } else if (lowSection !== '*' && highSection === '*') {
        condition.version_range_type = 'and_above'
        condition.version = `${lowSection}-*`
        condition.version_value = lowSection
      } else if (lowSection === '*' && highSection !== '*') {
        condition.version_range_type = 'and_below'
        condition.version = `*-${highSection}`
        condition.version_value = highSection
      } else if (lowSection === highSection) {
        condition.version_range_type = 'exactly'
        condition.version = lowSection
        condition.version_value = lowSection
      } else {
        // Unknown range format - default to any
        condition.version_range_type = 'any'
        condition.version = '*'
        condition.version_value = ''
      }
    } else {
      condition.version_range_type = 'any'
      condition.version = '*'
      condition.version_value = ''
    }
    
    conditions.push(condition)
  }
  
  // Hash conditions - create a separate FileHashCondition for each FileHash element
  const hashConditions = conditionsElem.querySelectorAll('FileHashCondition')
  for (const hashCond of hashConditions) {
    const fileHashElems = hashCond.querySelectorAll('FileHash')
    for (const fileHashElem of fileHashElems) {
      let hashData = fileHashElem.getAttribute('Data') || ''
      // Remove 0x prefix if present
      if (hashData.startsWith('0x') || hashData.startsWith('0X')) {
        hashData = hashData.substring(2)
      }
      
      conditions.push({
        type: 'FileHashCondition',
        file_hash: hashData,
        hash_type: fileHashElem.getAttribute('Type') || 'SHA256',
        source_file_name: fileHashElem.getAttribute('SourceFileName') || '',
        source_file_length: fileHashElem.getAttribute('SourceFileLength') || null,
      })
    }
  }
  
  // Parse exceptions (for FilePathRule)
  const exceptions = []
  const exceptionsElem = ruleElem.querySelector('Exceptions')
  if (exceptionsElem) {
    // Parse FilePathCondition exceptions
    const exceptionPaths = exceptionsElem.querySelectorAll('FilePathCondition')
    for (const excPath of exceptionPaths) {
      exceptions.push({
        type: 'FilePathCondition',
        path: excPath.getAttribute('Path') || '',
      })
    }
    
    // Parse FilePublisherCondition exceptions
    const exceptionPublishers = exceptionsElem.querySelectorAll('FilePublisherCondition')
    for (const excPub of exceptionPublishers) {
      const pubName = excPub.getAttribute('PublisherName') || '*'
      const productName = excPub.getAttribute('ProductName') || '*'
      const binaryName = excPub.getAttribute('BinaryName') || '*'
      
      const exception = {
        type: 'FilePublisherCondition',
        publisher_name: pubName,
        product_name: productName,
        binary_name: binaryName,
      }
      
      const versionElem = excPub.querySelector('BinaryVersionRange')
      if (versionElem) {
        const lowSection = versionElem.getAttribute('LowSection') || '*'
        const highSection = versionElem.getAttribute('HighSection') || '*'
        
        // Detect version range type
        if (lowSection === '*' && highSection === '*') {
          exception.version_range_type = 'any'
          exception.version = '*'
          exception.version_value = ''
        } else if (lowSection !== '*' && highSection === '*') {
          exception.version_range_type = 'and_above'
          exception.version = `${lowSection}-*`
          exception.version_value = lowSection
        } else if (lowSection === '*' && highSection !== '*') {
          exception.version_range_type = 'and_below'
          exception.version = `*-${highSection}`
          exception.version_value = highSection
        } else if (lowSection === highSection) {
          exception.version_range_type = 'exactly'
          exception.version = lowSection
          exception.version_value = lowSection
        } else {
          // Unknown range format - default to any
          exception.version_range_type = 'any'
          exception.version = '*'
          exception.version_value = ''
        }
      } else {
        exception.version_range_type = 'any'
        exception.version = '*'
        exception.version_value = ''
      }
      
      exceptions.push(exception)
    }
    
    // Parse FileHashCondition exceptions
    const exceptionHashes = exceptionsElem.querySelectorAll('FileHashCondition')
    for (const excHash of exceptionHashes) {
      const fileHashElems = excHash.querySelectorAll('FileHash')
      for (const fileHashElem of fileHashElems) {
        let hashData = fileHashElem.getAttribute('Data') || ''
        // Remove 0x prefix if present
        if (hashData.startsWith('0x') || hashData.startsWith('0X')) {
          hashData = hashData.substring(2)
        }
        
        exceptions.push({
          type: 'FileHashCondition',
          file_hash: hashData,
          hash_type: fileHashElem.getAttribute('Type') || 'SHA256',
          source_file_name: fileHashElem.getAttribute('SourceFileName') || '',
          source_file_length: fileHashElem.getAttribute('SourceFileLength') || null,
        })
      }
    }
  }
  
  return {
    id: ruleId,
    name,
    description,
    collection: collectionType,
    action,
    user_or_group_sid: userSid,
    conditions,
    exceptions: exceptions.length > 0 ? exceptions : [],
  }
}

/**
 * Export a single collection as XML (without AppLockerPolicy wrapper)
 */
export function exportCollection(collectionType, rules, enforcementMode = 'AuditOnly') {
  const doc = document.implementation.createDocument(null, null, null)
  const collectionElem = doc.createElement('RuleCollection')
  collectionElem.setAttribute('Type', collectionType)
  collectionElem.setAttribute('EnforcementMode', enforcementMode)
  doc.appendChild(collectionElem)
  
  // Add rules to collection
  for (const rule of rules) {
    const ruleElem = createRule(rule, doc)
    collectionElem.appendChild(ruleElem)
  }
  
  // Convert to XML string
  const serializer = new XMLSerializer()
  return serializer.serializeToString(collectionElem)
}

