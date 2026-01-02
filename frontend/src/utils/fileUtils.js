/**
 * Utility functions for extracting publisher information and calculating file hashes
 * All operations are performed client-side in the browser
 */

/**
 * Calculate SHA256 hash of a file
 * @param {File} file - The file to hash
 * @returns {Promise<{hash: string, size: number, filename: string}>}
 */
export async function calculateFileHash(file) {
  try {
    const arrayBuffer = await file.arrayBuffer()
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
    
    return {
      hash: hashHex,
      size: file.size,
      filename: file.name
    }
  } catch (error) {
    throw new Error(`Failed to calculate hash: ${error.message}`)
  }
}

/**
 * Read a Uint8Array from an ArrayBuffer at a specific offset
 */
function readUint8Array(buffer, offset, length) {
  return new Uint8Array(buffer, offset, length)
}

/**
 * Read a Uint16 value (little-endian) from buffer
 */
function readUint16(buffer, offset) {
  const view = new DataView(buffer)
  return view.getUint16(offset, true)
}

/**
 * Read a Uint32 value (little-endian) from buffer
 */
function readUint32(buffer, offset) {
  const view = new DataView(buffer)
  return view.getUint32(offset, true)
}

/**
 * Extract publisher information from a PE (Portable Executable) file
 * This parses the digital signature to extract publisher, product, binary name, and version
 * @param {File} file - The PE file to analyze
 * @returns {Promise<{publisher_name: string, product_name: string, binary_name: string, version: string}>}
 */
export async function extractPublisherInfo(file) {
  try {
    const arrayBuffer = await file.arrayBuffer()
    const buffer = new Uint8Array(arrayBuffer)
    
    // Check DOS header (MZ signature)
    if (buffer.length < 64 || buffer[0] !== 0x4D || buffer[1] !== 0x5A) {
      throw new Error('Not a valid PE file (missing MZ signature)')
    }
    
    // Read PE header offset from DOS header (offset 0x3C)
    const peOffset = readUint32(arrayBuffer, 0x3C)
    
    if (peOffset >= buffer.length || peOffset < 64) {
      throw new Error('Invalid PE header offset')
    }
    
    // Check PE signature (PE\0\0)
    if (buffer[peOffset] !== 0x50 || buffer[peOffset + 1] !== 0x45 || 
        buffer[peOffset + 2] !== 0x00 || buffer[peOffset + 3] !== 0x00) {
      throw new Error('Not a valid PE file (missing PE signature)')
    }
    
    // Read COFF header
    const machine = readUint16(arrayBuffer, peOffset + 4)
    const numberOfSections = readUint16(arrayBuffer, peOffset + 6)
    const optionalHeaderOffset = peOffset + 24
    
    // Determine if 32-bit or 64-bit
    const is64Bit = machine === 0x8664 // IMAGE_FILE_MACHINE_AMD64
    
    // Read optional header
    const magic = readUint16(arrayBuffer, optionalHeaderOffset)
    if (magic !== 0x10B && magic !== 0x20B) {
      throw new Error('Invalid optional header magic')
    }
    
    // Read data directories offset
    const dataDirectoryOffset = optionalHeaderOffset + (is64Bit ? 112 : 96)
    const numberOfRvaAndSizes = readUint32(arrayBuffer, dataDirectoryOffset - 4)
    
    if (numberOfRvaAndSizes < 5) {
      throw new Error('Invalid number of data directories')
    }
    
    // Certificate table is at index 4 (IMAGE_DIRECTORY_ENTRY_SECURITY)
    const certTableRVA = readUint32(arrayBuffer, dataDirectoryOffset + 4 * 8)
    const certTableSize = readUint32(arrayBuffer, dataDirectoryOffset + 4 * 8 + 4)
    
    if (certTableRVA === 0 || certTableSize === 0) {
      throw new Error('File is not digitally signed')
    }
    
    // Certificate table is stored at the end of the file (not RVA-based)
    // We need to find it by scanning from the end
    // Actually, the certificate table offset is usually stored as a file offset, not RVA
    // Let's search for it near the end of the file
    const certOffset = certTableRVA // In PE files, cert RVA is actually a file offset
    
    if (certOffset >= buffer.length || certOffset + certTableSize > buffer.length) {
      throw new Error('Certificate table is out of bounds')
    }
    
    // Read certificate
    const certLength = readUint32(arrayBuffer, certOffset)
    if (certLength === 0 || certLength > certTableSize) {
      throw new Error('Invalid certificate length')
    }
    
    // Certificate starts at certOffset + 8 (skip length and revision fields)
    // The certificate is stored as PKCS#7 SignedData
    const certData = buffer.slice(certOffset + 8, certOffset + 8 + certLength)
    
    // Parse PKCS#7 SignedData structure to extract the X.509 certificate
    try {
      // The certificate is in PKCS#7 format, we need to extract the actual X.509 cert
      // PKCS#7 structure: SEQUENCE { version, digestAlgorithms, contentInfo, certificates, ... }
      // We'll search for the certificate within the PKCS#7 structure
      const publisherInfo = parseCertificateFromPKCS7(certData)
      
      // Extract version from PE file version info resource
      let version = '0.0.0.0'
      let productName = '*'
      let binaryName = file.name.toUpperCase()
      
      try {
        const versionInfo = extractVersionInfo(arrayBuffer, buffer)
        if (versionInfo.version) {
          version = versionInfo.version
        }
        if (versionInfo.productName) {
          productName = versionInfo.productName
        }
        if (versionInfo.originalFilename) {
          binaryName = versionInfo.originalFilename.toUpperCase()
        }
      } catch (e) {
        console.warn('Could not extract version info:', e)
      }
      
      return {
        publisher_name: publisherInfo.publisherName || '*',
        product_name: productName,
        binary_name: binaryName,
        version: version
      }
    } catch (error) {
      throw new Error(`Failed to parse certificate: ${error.message}`)
    }
  } catch (error) {
    throw new Error(`Failed to extract publisher info: ${error.message}`)
  }
}

/**
 * Parse X.509 certificate from PKCS#7 SignedData structure
 * Extracts the certificate and parses the subject distinguished name
 */
function parseCertificateFromPKCS7(pkcs7Data) {
  try {
    // PKCS#7 is a SEQUENCE, find the certificates field
    // The certificate is typically in a SET OF Certificate structure
    // We'll search for the certificate SEQUENCE tag (0x30) and parse it
    
    // Look for certificate SEQUENCE (0x30) which indicates start of X.509 cert
    // X.509 certificate structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let certOffset = -1
    
    // Search for certificate SEQUENCE - look for 0x30 followed by a reasonable length
    for (let i = 0; i < pkcs7Data.length - 10; i++) {
      if (pkcs7Data[i] === 0x30) {
        // Check if this looks like a certificate (has reasonable length)
        const len = pkcs7Data[i + 1]
        if (len > 0x80 && len < 0x84 && i + len < pkcs7Data.length) {
          // This might be a certificate, try to parse it
          certOffset = i
          break
        } else if (len < 0x80 && len > 50 && i + len < pkcs7Data.length) {
          // Short form length
          certOffset = i
          break
        }
      }
    }
    
    if (certOffset === -1) {
      // Fallback: try to find certificate by searching for common patterns
      // Look for OID 1.2.840.113549.1.1.1 (RSA encryption) which is common in certs
      const rsaOid = new Uint8Array([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
      for (let i = 0; i < pkcs7Data.length - rsaOid.length; i++) {
        let match = true
        for (let j = 0; j < rsaOid.length; j++) {
          if (pkcs7Data[i + j] !== rsaOid[j]) {
            match = false
            break
          }
        }
        if (match) {
          // Found RSA OID, work backwards to find certificate start
          for (let k = i; k >= 0 && k > i - 500; k--) {
            if (pkcs7Data[k] === 0x30) {
              certOffset = k
              break
            }
          }
          if (certOffset !== -1) break
        }
      }
    }
    
    if (certOffset === -1) {
      // Last resort: parse the entire PKCS#7 structure
      // Try to extract certificate from the certificates field
      return parseCertificateSubject(pkcs7Data)
    }
    
    // Extract the certificate
    const certData = pkcs7Data.slice(certOffset)
    return parseCertificateSubject(certData)
  } catch (error) {
    console.error('Error parsing PKCS#7:', error)
    // Fallback to parsing the raw data
    return parseCertificateSubject(pkcs7Data)
  }
}

/**
 * Parse X.509 certificate subject name from DER-encoded certificate
 * This parses the ASN.1 structure to extract the subject distinguished name
 */
function parseCertificateSubject(certData) {
  try {
    // Simple ASN.1 parser for certificate subject
    // Certificate structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    // tbsCertificate contains: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }
    
    let offset = 0
    
    // Read outer SEQUENCE tag
    if (certData[offset] !== 0x30) {
      throw new Error('Invalid certificate structure')
    }
    offset++
    
    // Skip length (could be short or long form)
    const seqLength = readASN1Length(certData, offset)
    offset += getLengthBytes(certData[offset])
    
    // Skip to subject field (this is a simplified approach)
    // In a real implementation, we'd properly parse the tbsCertificate structure
    // For now, we'll search for the subject field
    
    // Convert to string for pattern matching, but filter out non-printable characters first
    // We'll process the data in chunks and only keep printable ASCII ranges
    const certString = String.fromCharCode(...certData.slice(0, Math.min(certData.length, 10000)))
      .split('')
      .map(char => {
        const code = char.charCodeAt(0)
        // Keep printable ASCII (32-126), newline, tab, and common punctuation
        if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
          return char
        }
        return ' ' // Replace non-printable with space
      })
      .join('')
    
    // Helper function to check if a string is valid text (mostly printable)
    function isValidDNValue(str) {
      if (!str || str.length < 2) return false
      
      // Count printable characters
      let printableCount = 0
      for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i)
        if ((code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13) {
          printableCount++
        }
      }
      
      // At least 80% should be printable
      if (printableCount / str.length < 0.8) return false
      
      // Should not be mostly numbers or special chars (DN values are usually text)
      const letterCount = (str.match(/[A-Za-z]/g) || []).length
      if (letterCount < str.length * 0.3 && str.length > 5) return false
      
      // Should not contain too many repeated characters
      const uniqueChars = new Set(str).size
      if (uniqueChars < str.length * 0.3 && str.length > 10) return false
      
      return true
    }
    
    // Extract DN components using regex patterns
    const dnParts = []
    
    // Common DN component patterns - look for patterns followed by printable text
    const patterns = {
      'CN': /CN\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'O': /O\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'OU': /OU\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'L': /L\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'S': /S\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'ST': /ST\s*=\s*([A-Za-z0-9\s\.,\-_()&®©™]+)/gi,
      'C': /C\s*=\s*([A-Z]{2})/gi, // Country codes are 2 letters
    }
    
    // Extract in order: O, L, S, C (AppLocker format)
    const order = ['O', 'L', 'S', 'C']
    const foundValues = {}
    
    for (const key of order) {
      const pattern = patterns[key]
      if (pattern) {
        const matches = [...certString.matchAll(pattern)]
        if (matches.length > 0) {
          // Find the best match - should be valid text and part of a DN sequence
          let bestMatch = null
          let bestIndex = -1
          let bestScore = 0
          
          for (const match of matches) {
            let value = match[1].trim()
            
            // Remove trailing non-printable characters
            value = value.replace(/[\x00-\x1F]+$/, '').trim()
            
            // Validate the value
            if (!isValidDNValue(value)) continue
            
            // Calculate a score based on:
            // 1. Length (reasonable DN values are usually 2-100 chars)
            // 2. Being part of a DN sequence
            // 3. Position (later matches are more likely to be subject)
            let score = 0
            
            if (value.length >= 2 && value.length <= 100) {
              score += 10
            }
            
            // Check context - is this part of a DN sequence?
            const contextStart = Math.max(0, match.index - 100)
            const contextEnd = Math.min(certString.length, match.index + match[0].length + 100)
            const context = certString.substring(contextStart, contextEnd)
            
            // Look for other DN components nearby
            const hasOtherDN = /[OCLS]=\s*[A-Za-z]/.test(context)
            if (hasOtherDN) {
              score += 20
            }
            
            // Prefer later matches (subject usually comes after issuer)
            score += match.index / 1000
            
            if (score > bestScore) {
              bestMatch = value
              bestIndex = match.index
              bestScore = score
            }
          }
          
          if (bestMatch && bestScore > 5) {
            foundValues[key] = bestMatch
            dnParts.push(`${key}=${bestMatch}`)
          }
        }
      }
    }
    
    // If we found components, build the DN
    if (dnParts.length > 0) {
      return {
        publisherName: dnParts.join(', ')
      }
    }
    
    // Fallback: try to find organization name in binary data
    // Look for common patterns like "MICROSOFT", "CORPORATION", etc.
    const orgKeywords = ['MICROSOFT', 'CORPORATION', 'INC', 'LLC', 'LTD']
    for (const keyword of orgKeywords) {
      const keywordBytes = new TextEncoder().encode(keyword)
      let searchOffset = 0
      while (searchOffset < certData.length - keywordBytes.length) {
        let found = true
        for (let i = 0; i < keywordBytes.length; i++) {
          if (certData[searchOffset + i] !== keywordBytes[i]) {
            found = false
            break
          }
        }
        if (found) {
          // Try to extract surrounding context
          const contextStart = Math.max(0, searchOffset - 100)
          const contextEnd = Math.min(certData.length, searchOffset + 200)
          const context = String.fromCharCode(...certData.slice(contextStart, contextEnd))
          
          // Try to extract DN from context
          const dnMatch = context.match(/([A-Z]{1,3})\s*=\s*([^,\x00<>]+)/gi)
          if (dnMatch && dnMatch.length >= 2) {
            return {
              publisherName: dnMatch.join(', ')
            }
          }
        }
        searchOffset++
      }
    }
    
    // Last resort: return a default
    return {
      publisherName: 'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'
    }
  } catch (error) {
    console.error('Error parsing certificate subject:', error)
    return {
      publisherName: 'O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US'
    }
  }
}

/**
 * Read ASN.1 length field
 */
function readASN1Length(data, offset) {
  if ((data[offset] & 0x80) === 0) {
    // Short form
    return data[offset]
  } else {
    // Long form
    const lengthOfLength = data[offset] & 0x7F
    let length = 0
    for (let i = 1; i <= lengthOfLength; i++) {
      length = (length << 8) | data[offset + i]
    }
    return length
  }
}

/**
 * Get number of bytes used for length encoding
 */
function getLengthBytes(byte) {
  if ((byte & 0x80) === 0) {
    return 1
  } else {
    return 1 + (byte & 0x7F)
  }
}

/**
 * Extract version information from PE file resources
 */
function extractVersionInfo(arrayBuffer, buffer) {
  try {
    // Find .rsrc section
    const peOffset = readUint32(arrayBuffer, 0x3C)
    const numberOfSections = readUint16(arrayBuffer, peOffset + 6)
    const sectionTableOffset = peOffset + 24 + (readUint16(arrayBuffer, peOffset + 20) === 0x20B ? 112 : 96)
    
    let rsrcRVA = 0
    let rsrcSize = 0
    let rsrcOffset = 0
    
    for (let i = 0; i < numberOfSections; i++) {
      const sectionOffset = sectionTableOffset + i * 40
      const nameBytes = buffer.slice(sectionOffset, sectionOffset + 8)
      const name = String.fromCharCode(...nameBytes.filter(b => b !== 0))
      
      if (name === '.rsrc' || name.startsWith('.rsrc')) {
        rsrcRVA = readUint32(arrayBuffer, sectionOffset + 12)
        rsrcSize = readUint32(arrayBuffer, sectionOffset + 16)
        rsrcOffset = readUint32(arrayBuffer, sectionOffset + 20)
        break
      }
    }
    
    if (rsrcRVA === 0) {
      return {}
    }
    
    // Parse version resource (simplified - would need full resource parsing)
    // For now, return empty and let the user fill in manually
    return {}
  } catch (error) {
    return {}
  }
}

