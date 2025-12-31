<#
.SYNOPSIS
    Reads Intune/MDM AppLocker policies and outputs either a readable table or full XML.
.DESCRIPTION
    Detects all Policy files under C:\Windows\System32\AppLocker\MDM
    and merges them for display.
.PARAMETER Xml
    Switch. If provided, outputs the full merged XML instead of a table.
#>

param(
    [switch]$Xml
)

$mdmRoot = "C:\Windows\System32\AppLocker\MDM"

# Function to load a single Policy file as XML
function Get-MDMPolicyXml {
    param([string]$filePath)

    if (-Not (Test-Path $filePath)) { return $null }

    try {
        # Read file as bytes and decode as Unicode
        $bytes = Get-Content -Path $filePath -Encoding Byte -ErrorAction Stop
        if ($bytes.Length -eq 0) { return $null }

        $text = [System.Text.Encoding]::Unicode.GetString($bytes) -replace "`0",""
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
}
