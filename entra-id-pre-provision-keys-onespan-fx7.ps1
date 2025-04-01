<#
.SYNOPSIS
    Supports two workflows for managing FIDO2 credentials in Entra ID using Microsoft Graph:
    1. Generates FIDO2 challenges per user for OneSpan pre-provisioning.
    2. Registers pre-provisioned FIDO2 keys to Entra users.
    Supports DryRun and Force modes for automation and testing.

.DESCRIPTION
    - Challenge Generation Mode:
        Reads UPNs from a CSV, queries their User IDs, and requests FIDO2 credential creation options.
        Outputs a CSV with UserID and the generated challenge for OneSpan.

    - Credential Registration Mode:
        Reads a CSV with FIDO2 credential data returned from OneSpan,
        validates required columns, checks for existing assignments, and registers the credentials.

.PARAMETER Mode
    REQUIRED: Must be either 'generate-challenges' or 'register-credentials'.

.PARAMETER TenantId
    REQUIRED: The Microsoft Entra ID Tenant GUID.

.PARAMETER CsvPath
    REQUIRED: Path to the input CSV file.

.PARAMETER OutputPath
    Optional: Output CSV file path (only used in 'generate-challenges' mode, default is current directory 'fido2-challenges-output.csv').

.PARAMETER VerboseLogging
    Optional: Enables verbose debug logging if specified.

.PARAMETER LogPath
    Optional: File path to write detailed logs.

.PARAMETER DryRun
    Optional: Performs all validation and logging without making changes to Entra ID or saving files.

.PARAMETER Force
    Optional: Skips the user confirmation prompt when registering FIDO2 credentials.
    Useful for automation or scripting scenarios where manual input is not desired.

.EXAMPLE
    .\entra-id-pre-provision-keys-onespan-fx7.ps1 -Mode "generate-challenges" -TenantId "7c440c6b-..." -CsvPath "C:\Users\user1\Downloads\users.csv" -OutputPath "C:\Users\user1\Downloads\toOneSpan.csv" -VerboseLogging
    .\entra-id-pre-provision-keys-onespan-fx7.ps1 -Mode "register-credentials" -TenantId "7c440c6b-..." -CsvPath "C:\Users\user1\Downloads\tokens.csv" -VerboseLogging

.NOTES
    Author: Will LaSala (OneSpan)
    Company: OneSpan
    License: MIT
    Dependencies: Microsoft.Graph.Beta
    Version: 1.0.0
    CSV Schema (generate-challenges):
        - userPrincipalName

    CSV Schema (register-credentials):
        - userId
        - serialNumber
        - credentialId
        - attestationObject
        - clientDataJson

.PRIVACY
    No telemetry or data is collected. All operations remain local unless interacting with Microsoft Graph.
#>

param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("generate-challenges", "register-credentials")]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$LogPath,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun,

    [Parameter(Mandatory = $false)]
    [switch]$VerboseLogging,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

$debugMode = $VerboseLogging -eq $true
$logOutputFileName = "OneSpan-FIDO2-Registration-Debug-$(Get-Date -Format 'yyyyMMddHHmm').log"

$requiredRegistrationColumns = @(
    "userId", "serialNumber", "credentialId", "attestationObject", "clientDataJson"
)

$requiredUPNColumns = @(
    "userPrincipalName"
)

# -------------------------------------
# 🔧 Logging
# -------------------------------------
function Test-LogPath {
    if ($LogPath -and -not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
        } catch {
            throw "❌ Failed to create log directory at ${LogPath}: $_"
        }
    }
}

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]$msg,
        [Parameter(Mandatory = $false)][string]$ForegroundColor,
        [Parameter(Mandatory = $false)][string]$type
    )
    $fileOutputMsg = $msg
    if ($debugMode -and -not $type) {
        Write-Host "[DEBUG] $msg" -ForegroundColor Yellow
        $fileOutputMsg = "[DEBUG] $msg"
    }
    if($type -eq "Host"){
        if($ForegroundColor){
            Write-Host $msg -ForegroundColor $ForegroundColor
        }else{
            Write-Host $msg
        }
        $fileOutputMsg = "[INFO] $msg"
    }
    if($type -eq "Error"){
        Write-Error $msg
        $fileOutputMsg = "[ERROR] $msg"
    }
    if($type -eq "Warn"){
        Write-Warning $msg
        $fileOutputMsg = "[WARN] $msg"
    }
    if ($LogPath) {
        $LogOutputPath = Join-Path -Path $LogPath -ChildPath $logOutputFileName
        Add-Content -Path $LogOutputPath -Value "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss.fff'): $fileOutputMsg"
    }
}

# -------------------------------------
# ✅ Module Setup
# -------------------------------------
function Install-ModuleIfNeeded {
    param ([string]$ModuleName)
    if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
        $PSMajorVersion = if ($PSVersionOverride) { $PSVersionOverride } else { $PSVersionTable.PSVersion.Major }
        Write-Log "📦 Installing module: $ModuleName" -type "Host"
        if ($PSMajorVersion -lt 7) {
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        } else {
            Install-PSResource -Name $ModuleName -Scope CurrentUser -ErrorAction Stop
        }
    }
}

function Connect-ToMsGraph {
    param ([string]$TenantId)
    try {
        Write-Log "🔗 Connecting to Microsoft Graph with Tenant ID: $TenantId" -type "Host"
        Connect-MgGraph -Scopes "UserAuthenticationMethod.ReadWrite.All" -TenantId $TenantId -ErrorAction Stop
        Write-Log "✅ Connected to Microsoft Graph." -type "Host"
    } catch {
        Write-Log "❌ Failed to connect to Microsoft Graph: $_" -type "Error"
        throw "❌ Failed to connect to Microsoft Graph: $_"
    }
}

function Confirm-Action {
    param (
        [string]$Message,
        [switch]$Force
    )
    if (-not $DryRun -and -not $Force) {
        $confirmation = Read-Host "$Message (Y/N)"
        Write-Host "CONFIRMATION: $confirmation"
        if ($confirmation -notin @("Y", "y")) {
            Write-Log "❌ Operation cancelled by user." -type "Host"
            throw "❌ Operation cancelled by user."
        }
    } elseif ($Force) {
        Write-Log "⚠️ Force flag detected. Skipping confirmation prompt." -type "Warn"
    } elseif ($DryRun) {
        Write-Log "⚠️ Dry Run flag detected. Skipping confirmation prompt." -type "Warn"
    }
    return $true
}

# -------------------------------------
# 📄 CSV Processing
# -------------------------------------
function Test-CsvHeader {
    param ($csv,[switch]$GenChallenge)
    $requiredColumns = @()
    if($GenChallenge){
        $requiredColumns = $requiredUPNColumns
    }else{
        $requiredColumns = $requiredRegistrationColumns
    }
    foreach ($col in $requiredColumns) {
        if (-not ($csv | Get-Member -Name $col)) {
            throw "❌ Missing required column: $col"
        }
    }
}

function Test-CsvRow {
    param (
        [psobject]$row,
        [switch]$GenChallenge
    )
    $requiredColumns = @()
    if($GenChallenge){
        $requiredColumns = $requiredUPNColumns
    }else{
        $requiredColumns = $requiredRegistrationColumns
    }
    foreach ($field in $requiredColumns) {
        if ([string]::IsNullOrWhiteSpace($row.$field)) {
            Write-Log "   ⚠️ Missing required value for '$field' in row: $($row | ConvertTo-Json -Compress)" -type "Warn"
            return $false
        }
    }
    Write-Log "   ✅ CSV row is valid."
    return $true
}


function Import-CsvData {
    param (
        [string]$path,
        [switch]$GenChallenge
    )
    if (-not (Test-Path $path)) {
        throw "❌ CSV not found at path: $path"
    }
    $csv = Import-Csv -Path $path
    if($GenChallenge){
        Test-CsvHeader -csv $csv -GenChallenge | Out-Null
    }else{
        Test-CsvHeader -csv $csv | Out-Null
    }
    return $csv
}

# -------------------------------------
# 🔐 Credential Handling
# -------------------------------------
function Get-UserIdFromUpn {
    param ([Parameter(Mandatory=$true)][string]$upn)
    if ([string]::IsNullOrWhiteSpace($upn))         { throw "❌ upn is required and must be a string." }
    try {
        Write-Log "   🔍 Looking up UserID from UPN: $upn"
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ConsistencyLevel eventual -CountVariable count -ErrorAction Stop
        if ($user.Count -eq 0) { throw "❌ User not found: $upn" }
        Write-Log "   ✅ User ID found: $($user.Id)"
        return $user.Id
    } catch {
        Write-Log "❌ Could not locate user for: $upn" -type "Error"
        return $null
    }
}

function Get-UpnFromUserId {
    param ([Parameter(Mandatory = $true)][string]$userId)
    if ([string]::IsNullOrWhiteSpace($userId))         { throw "❌ userId is required and must be a string." }
    try {
        Write-Log "   🔍 Looking up UPN from UserID: $userId"
        $user = Get-MgUser -UserId $userId -ErrorAction Stop
        if (-not $user -or [string]::IsNullOrWhiteSpace($user.UserPrincipalName)) {
            throw "❌ No UPN found for userId: $userId"
        }
        Write-Log "   ✅ Found UPN: $($user.UserPrincipalName)"
        return $user.UserPrincipalName
    } catch {
        throw "❌ Failed to retrieve UPN for userId ${userId}: $_"
    }
}

function Get-Fido2CredentialCreationOptions {
    param (
        [Parameter(Mandatory=$true)][string]$userId,

        [int]$challengeTimeoutInMinutes = 43200
    )
    if ([string]::IsNullOrWhiteSpace($userId))         { throw "❌ userId is required and must be a string." }
    try {
        $uri = "/beta/users/$userId/authentication/fido2Methods/creationOptions?challengeTimeoutInMinutes=$challengeTimeoutInMinutes"
        Write-Log "   🌐 Requesting creation options from $uri"
        return Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Json
    } catch {
        Write-Log "❌ Error retrieving credential creation options: $_" -type "Error"
        return $null
    }
}

function Get-ExistingFido2Credentials {
    param ([Parameter(Mandatory=$true)][string]$userId)
    if ([string]::IsNullOrWhiteSpace($userId))         { throw "❌ userId is required and must be a string." }
    try {
        $responses = Get-MgUserAuthenticationFido2Method -UserId $userId
        if ($responses.Count -gt 0) {
            Write-Log "   ❕ FIDO2 methods found for userId ${userId}:"
            foreach ($response in $responses) {
                $formatted = $response | Format-List | Out-String
                Write-Log "   ----`n$formatted"
            }
        } else {
            Write-Log "   ✅ No FIDO2 methods found for userId $userId."
        }
        return $responses
    } catch {
        Write-Log "❌ Failed to fetch FIDO2 methods for ${userId}: $_" -type "Error"
        return @()
    }
}

function Test-CredentialAlreadyAssigned {
    param (
        [string]$userId,
        [string]$cId, # Credential ID
        [string]$displayName
    )
    $existingMethods = Get-ExistingFido2Credentials -userId $userId
    return $existingMethods | Where-Object {
        $_.id -eq $cId -or $_.displayName -eq $displayName
    }
}

function Register-Fido2Credential {
    param (
        [Parameter(Mandatory=$true)][string]$userId,
        [Parameter(Mandatory=$true)][string]$displayName,
        [Parameter(Mandatory=$true)][string]$cId, # Credential ID
        [Parameter(Mandatory=$true)][string]$clientDataJson,
        [Parameter(Mandatory=$true)][string]$attestationObject
    )

    if ([string]::IsNullOrWhiteSpace($userId))         { throw "❌ userId is required and must be a string." }
    if ([string]::IsNullOrWhiteSpace($displayName))    { throw "❌ displayName is required." }
    if ([string]::IsNullOrWhiteSpace($cId))            { throw "❌ credentialId is required." }
    if ([string]::IsNullOrWhiteSpace($clientDataJson)) { throw "❌ clientDataJson is required." }
    if ([string]::IsNullOrWhiteSpace($attestationObject)) { throw "❌ attestationObject is required." }

    try {
        $uri = "/beta/users/$userId/authentication/fido2Methods"
        $payload = @{
            displayName = $displayName
            publicKeyCredential = @{
                id = $cId
                response = @{
                    clientDataJSON = $clientDataJson
                    attestationObject = $attestationObject
                }
            }
        } | ConvertTo-Json -Depth 5 -Compress

        Write-Log "   🌐 Posting registration to $uri"
        Write-Log "      Payload Length: $($payload.Length)"

        if ($DryRun) {
            Write-Log "[DryRun] Simulating registration for $userId" -type "Host"
            return $true
        }

        $response = Invoke-MgGraphRequest `
            -Method POST `
            -Uri $uri `
            -ContentType 'application/json; charset=utf-8' `
            -Body $payload `
            -OutputType Json

        return $response
    } catch {
        Write-Log "❌ Error registering credential for ${userId}: $_" -type "Error"
        return $null
    }
}

# -------------------------------------
# 🧠 Main Execution Logic
# -------------------------------------
function Invoke-UserGenerateChallenges {
    param ($csv)

    $outputRows = @()

    foreach ($row in $csv) {
        Write-Log "1. ⏳ Checking CSV row to ensure it is valid"
        if (-not (Test-CsvRow -row $row -GenChallenge)) {
            continue
        }
        $upn = $row.userPrincipalName

        Write-Log "2. ⏳ Looking up UserID from UPN"
        $userId = Get-UserIdFromUpn -upn $upn
        if (-not $userId) { continue }
        Write-Log "   ✅ User Principal Name: $upn => User Object ID: $userId"

        Write-Log "3. ⏳ Getting FIDO2 creation options from MS Graph"
        $creationOptions = Get-Fido2CredentialCreationOptions -userId $userId
        if (-not $creationOptions) { continue }
        Write-Log "   ✅ MS Graph FIDO2 Credential Creation Options: $creationOptions"

        $parsed = $creationOptions | ConvertFrom-Json
        $challenge = $parsed.publicKey.challenge

        $outputRows += [pscustomobject]@{
            UserId            = $userId
            Challenge         = $challenge
        }
    }

    try {
        if ($outputRows.Count -eq 0) {
            throw "No challenges generated. Export aborted."
        }
        if ($DryRun) {
            Write-Log "[DryRun] Skipping file export." -type "Host"
            return
        }
        $outputRows | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        Write-Log "📤 Exported challenges to $OutputPath" -ForegroundColor Cyan -type "Host"
    } catch {
        Write-Log "❌ Failed to export challenges: $_" -type "Error"
    }
}

function Invoke-UserRegistrations {
    param ($csv)

    if (-not (Confirm-Action "This will register FIDO2 keys to Entra users. Continue?" -Force:$Force)) {
        return
    }

    $successCount = 0
    $failureCount = 0

    foreach ($row in $csv) {
        Write-Log "1. ⏳ Checking CSV row to ensure it is valid"
        if (-not (Test-CsvRow -row $row)) {
            $failureCount++
            continue
        }
        $userId = $row.userId
        $serial = $row.serialNumber
        $credentialId = $row.credentialId
        $clientDataJson = $row.clientDataJson
        $attestationObject = $row.attestationObject

        $displayName = "OneSpan FX7 - $serial"

        try {
            Write-Log "2. ⏳ Checking to ensure UserID is still valid"
            $upn = Get-UpnFromUserId -userId $userId
        } catch {
            Write-Log "⚠️ Could not resolve UPN for userId $userId, skipping this row $_" -type "Warn"
            $failureCount++
            continue
        }

        Write-Log "3. ⏳ Checking for existing credentials"
        if (Test-CredentialAlreadyAssigned -userId $userId -cId $credentialId -displayName $displayName) {
            Write-Log "   ⚠️ Credential already assigned to $upn, skipping this row $_" -type "Warn"
            $failureCount++
            continue
        }

        Write-Log "4. ⏳ Registering new credential"
        $result = Register-Fido2Credential -userId $userId `
                                           -displayName $displayName `
                                           -cId $credentialId `
                                           -clientDataJson $clientDataJson `
                                           -attestationObject $attestationObject

        Write-Log "   🔍 Results of registration: $result"

        if ($result) {
            Write-Log "✅ Registered FIDO2 key, $displayName, for $upn" -ForegroundColor Green -type "Host"
            $successCount++
        } else {
            Write-Log "❌ Failed to register FIDO2 key, $displayName, for $upn" -type "Error"
            $failureCount++
        }
    }
    Write-Log "🎉 Summary:" -ForegroundColor Cyan -type "Host"
    Write-Log "   ✅ Successfully registered tokens: $successCount" -ForegroundColor Green -type "Host"
    Write-Log "   ❌ Failed/Skipped registrations: $failureCount" -ForegroundColor Red -type "Host"
}

# =============================
# 🚀 SCRIPT ENTRY POINT
# =============================
function Main {
    param (
        [string]$Mode,
        [string]$TenantId,
        [string]$CsvPath,
        [string]$LogPath,
        [string]$logOutputFileName = "OneSpan-FIDO2-Registration-Debug-$(Get-Date -Format 'yyyyMMddHHmm').log",
        [bool]$DryRun,
        [bool]$Force = $false
    )

    if ($LogPath) {
        Test-LogPath
        Write-Log "Logging to file: $(Join-Path -Path $LogPath -ChildPath $logOutputFileName)" -type "Host"
    }

    Install-ModuleIfNeeded -ModuleName "Microsoft.Graph.Beta"
    Connect-ToMsGraph -TenantId $TenantId

    if ($Mode -eq "generate-challenges") {
        if (-not $OutputPath) {
            $OutputPath = Join-Path -Path $PSScriptRoot -ChildPath "fido2-challenges-output-$(Get-Date -Format 'yyyyMMddHHmmss').csv"
        }
        $csvInput = Import-CsvData -path $CsvPath -GenChallenge
        Invoke-UserGenerateChallenges -csv $csvInput
    }
    elseif ($Mode -eq "register-credentials") {
        $csvData = Import-CsvData -path $CsvPath
        Invoke-UserRegistrations -csv $csvData
    }
    else {
        throw "❌ Invalid mode. Use 'generate-challenges' or 'register-credentials'."
    }
}

# ------------------------------
# ✅ TEST MODE GUARD CLAUSE
# ------------------------------
# This code is covered in the unit tests, but coverage reports do not pick this up.
if (-not $env:TEST_MODE -and $MyInvocation.InvocationName -ne '.') {
    Main @PSBoundParameters
}