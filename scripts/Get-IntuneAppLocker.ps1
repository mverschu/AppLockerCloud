$mdmRoot = "C:\Windows\System32\AppLocker\MDM"

function Parse-MDMPolicyFile {
    param([string]$filePath, [string]$ruleType)

    if (-Not (Test-Path $filePath)) { return @() }

    try {
        # Read as Unicode and remove nulls
        $bytes = Get-Content -Path $filePath -Encoding Byte -ErrorAction Stop
        $text = [System.Text.Encoding]::Unicode.GetString($bytes) -replace "`0",""

        [xml]$xml = $text

        $results = @()

        foreach ($rule in $xml.RuleCollection.ChildNodes) {
            # Some rules may not have Name/UserOrGroupSid/Action; handle safely
            $results += [PSCustomObject]@{
                RuleType       = $ruleType
                RuleClass      = $rule.Name
                Name           = $rule.GetAttribute("Name")
                Action         = $rule.GetAttribute("Action")
                UserOrGroupSid = $rule.GetAttribute("UserOrGroupSid")
            }
        }

        return $results
    }
    catch {
        Write-Warning ("Failed to parse file " + $filePath + ": " + $_.Exception.Message)
        return @()
    }
}

# Find all Policy files
$policyFiles = Get-ChildItem -Path $mdmRoot -Recurse -Filter "Policy" -File

if ($policyFiles.Count -eq 0) {
    Write-Host "No AppLocker policies found under $mdmRoot"
    return
}

$allRules = @()
foreach ($policyFile in $policyFiles) {
    $ruleType = ($policyFile.DirectoryName -split '\\')[-1]
    $allRules += Parse-MDMPolicyFile -filePath $policyFile.FullName -ruleType $ruleType
}

if ($allRules.Count -gt 0) {
    $allRules | Sort-Object RuleType, Name | Format-Table -AutoSize
}
else {
    Write-Host "No rules found in the Intune/MDM AppLocker policies."
}
