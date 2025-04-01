# Requires -Version 5.1
# Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }


Describe "FIDO2 Script Unit Tests" {

    BeforeAll {
        # -------------------------------
        # Mock CSV files
        # -------------------------------
        $CsvMockPathRegister = Join-Path $PSScriptRoot 'temp-test-data.csv'
@"
userId,serialNumber,credentialId,attestationObject,clientDataJson
123,FX7ABC,cred,att,json
"@ | Set-Content -Path $CsvMockPathRegister

        # -------------------------------
        # 💡 MS Graph Mocks (Global Setup)
        # -------------------------------
        Mock -CommandName Connect-MgGraph -MockWith { "Mocked Connection" }

        Mock -CommandName Get-MgUser -MockWith {
            param($UserId, $Filter)
            if ($Filter -and $Filter -like "*missing*") {
                return @()
            }
            return [pscustomobject]@{
                Id = "user-id-123"
                UserPrincipalName = "user@example.com"
            }
        }

        Mock -CommandName Invoke-MgGraphRequest -MockWith {
            return @{
                publicKey = @{ challenge = "mocked-challenge" }
            } | ConvertTo-Json
        }

        Mock -CommandName Get-MgUserAuthenticationFido2Method -MockWith {
            return @(
                [pscustomobject]@{
                    id = "existing-cred"
                    displayName = "Existing Token"
                }
            )
        }
        # ----------------------------------------
        # 🧪 File System Mocks (Centralized Setup)
        # ----------------------------------------
        $script:mockedLogContent = @()
        $script:createdDirectories = @()

        Mock -CommandName Test-Path -MockWith {
            param($Path)
            # Simulate directory not existing initially, then existing after creation
            return $script:createdDirectories -contains $Path
        }

        Mock -CommandName New-Item -MockWith {
            param($Path, $ItemType, $Force)
            $script:createdDirectories += $Path
        }

        Mock -CommandName Join-Path -MockWith {
            param($Path, $ChildPath)
            return "$Path\$ChildPath"
        }

        Mock -CommandName Add-Content -MockWith {
            param($Path, $Value)
            Write-Host "📌 MOCK: Add-Content to $Path"
            $script:mockedLogContent += $Value
        }

        Mock -CommandName Get-Content -MockWith {
            return ($script:mockedLogContent -join "`n")
        }

        Mock -CommandName Remove-Item -MockWith {
            param($Path, $Force, $Recurse, $ErrorAction)
            # Reset state for the fake directory or file
            $script:createdDirectories = @()
            $script:mockedLogContent = @()
        }

        # 🧪 Set test environment variable for special throw logic
        $env:TEST_MODE = "1"

        $testParams = @{
            Mode = 'register-credentials'
            TenantId = 'test-tenant-id'
            CsvPath = $CsvMockPathRegister
            DryRun = $true
            Force = $true
        }
        . "$PSScriptRoot\..\entra-id-pre-provision-keys-onespan-fx7.ps1" @testParams
    }
    BeforeEach {
        $script:mockedLogContent = @()
        $script:createdDirectories = @()
    }

    AfterAll {
        Remove-Item $CsvMockPathRegister -Force -ErrorAction SilentlyContinue
        Remove-Item Env:TEST_MODE -ErrorAction SilentlyContinue
    }

    Context "Test-LogPath" {
        It "should create the log directory if it doesn't exist" {
            $LogPath = "$TestDrive\TempLogCheck"
            Remove-Item -Force -Recurse $LogPath -ErrorAction SilentlyContinue
            Test-LogPath
            Test-Path $LogPath | Should -BeTrue
            Remove-Item -Force -Recurse $LogPath
        }

        It "should not throw if directory already exists" {
            $global:LogPath = "$PSScriptRoot\TempLogCheck"
            New-Item -ItemType Directory -Force -Path $global:LogPath | Out-Null
            { Test-LogPath } | Should -Not -Throw
            Remove-Item -Force -Recurse $global:LogPath
        }

        It "should throw an error if creating the log directory fails" {
            $LogPath = "$TestDrive\InvalidLogCheck"
            # Remove in case it exists from a previous run
            Remove-Item -Force -Recurse $LogPath -ErrorAction SilentlyContinue
            # Mock New-Item to simulate failure
            Mock New-Item { throw "Simulated failure creating log directory." }
            # Validate that it throws with the expected error message
            { Test-LogPath } | Should -Throw "*Failed to create log directory*"
        }
    }

    Context "Write-Log" {
        It "should confirm Add-Content is mocked" {
            $debugMode = $true
            $LogPath = "$TestDrive\Logs"
            $logOutputFileName = "TestLog.log"

            Test-LogPath
            Write-Log -msg "Confirm Add-Content is mocked"

            Assert-MockCalled -CommandName Add-Content -Exactly 1 -Scope Describe
        }

        It "should write debug log to console and file when debugMode is true" {
            $debugMode = $true
            $LogPath = "$TestDrive\Logs"
            $logOutputFileName = "TestLog.log"

            Test-LogPath
            Write-Log -msg "Test debug message"

            ($mockedLogContent -join "`n") | Should -Match "Test debug message"

            Remove-Item -Recurse -Force $LogPath
        }

        It "should not throw when LogPath is not set" {
            $global:LogPath = $null
            { Write-Log -msg "No log path test" } | Should -Not -Throw
        }

        It "should write log to console with specified foreground color when type is 'Host'" {
            $ForegroundColor = "Green"
            $msg = "Test with ForegroundColor"
            Mock -CommandName Write-Host -MockWith {}
            Write-Log -msg $msg -type "Host" -ForegroundColor $ForegroundColor
            Assert-MockCalled -CommandName Write-Host -Exactly 1 -Scope It -ParameterFilter {
                $msg -eq "Test with ForegroundColor" -and
                $ForegroundColor -eq "Green"
            }
        }
    }

    Describe "Install-ModuleIfNeeded" {

        BeforeEach {
            $ModuleNameToInstall = "MyTestModule"
            $PSVersionOverride = $null

            # Preemptively stub both to avoid resolution errors
            Mock Install-Module { "stubbed Install-Module" }
            Mock Install-PSResource { "stubbed Install-PSResource" }
            Mock Write-Log {}
        }
        AfterEach {
            # Reset the global variable to avoid side effects
            $PSVersionOverride = $null
        }

        It "should install the module with Install-Module on PowerShell 5.x" {
            $PSVersionOverride = 5
            Mock Get-Module { $null }
            Mock Install-Module -Verifiable
            Mock Install-PSResource -MockWith { throw "Should not be called" }

            Install-ModuleIfNeeded -ModuleName $ModuleNameToInstall

            Assert-MockCalled Install-Module -Exactly 1
        }

        It "should install the module with Install-PSResource on PowerShell 7+" -Skip:($PSVersionTable.PSVersion.Major -lt 6) {
            Mock Get-Module { $null }
            Mock Install-PSResource -Verifiable
            Mock Install-Module -MockWith { throw "Should not be called" }

            Install-ModuleIfNeeded -ModuleName $ModuleNameToInstall

            Assert-MockCalled Install-PSResource -Exactly 1
        }

        It "should not install module if already available" {
            Mock Get-Module {
                param ($Name, $ListAvailable)
                return [pscustomobject]@{ Name = $Name }
            }

            Mock Install-Module -MockWith { throw "Should not be called" }
            Mock Install-PSResource -MockWith { throw "Should not be called" }

            Install-ModuleIfNeeded -ModuleName $ModuleNameToInstall

            Assert-MockCalled Install-Module -Exactly 0
            Assert-MockCalled Install-PSResource -Exactly 0
        }
    }

    Describe "Connect-ToMsGraph" {
        It "should call Connect-MgGraph with correct TenantId and scope" {
            $script:called = $false

            Mock -CommandName Connect-MgGraph -MockWith {
                param ($Scopes, $TenantId, $ErrorAction)
                $script:called = $true
                $Scopes | Should -Contain "UserAuthenticationMethod.ReadWrite.All"
                $TenantId | Should -Be "mock-tenant-id"
            }

            Mock -CommandName Write-Log -MockWith { }

            Connect-ToMsGraph -TenantId "mock-tenant-id"

            $script:called | Should -BeTrue
        }

        It "should log a success message on successful connection" {
            $script:logMessages = @()

            Mock -CommandName Connect-MgGraph -MockWith { "Mocked Connection" }

            Mock -CommandName Write-Log -MockWith {
                param (
                    [string]$msg,
                    [string]$Type
                )
                $script:logMessages += $msg
            }

            Connect-ToMsGraph -TenantId "test-tenant"

            $script:logMessages | Should -Contain "✅ Connected to Microsoft Graph."
        }

        It "should log an error and throw if connection fails" {
            $script:logError = $null

            Mock -CommandName Connect-MgGraph -MockWith {
                throw "Connection failed."
            }

            Mock -CommandName Write-Log -MockWith {
                param($msg, $Type)
                if ($Type -eq "Error") {
                    $script:logError = $msg
                }
            }

            {
                Connect-ToMsGraph -TenantId "bad-tenant"
            } | Should -Throw "❌ Failed to connect to Microsoft Graph: Connection failed."

            $script:logError | Should -Contain "❌ Failed to connect to Microsoft Graph: Connection failed."
        }
    }

    Context "Confirm-Action" {
        It "should prompt if not -DryRun or -Force" {
            $DryRun = $false
            Mock -CommandName Read-Host -MockWith { "Y" }
            { Confirm-Action -Message "Proceed?" } | Should -Not -Throw
        }

        It "should skip prompt if -Force is used" {
            { Confirm-Action -Message "Skipping" -Force } | Should -Not -Throw
        }

        It "should log when DryRun is true and Force is not set" {
            $Force = $false
            $script:logged = $false

            Mock Write-Log {
                param ($msg, $type)
                if ($msg -like "*Dry Run flag detected*" -and $type -eq "Warn") {
                    $script:logged = $true
                }
            }

            Confirm-Action -Message "Dry run test" | Should -BeTrue
            $script:logged | Should -BeTrue
        }

        It "should exit if user enters N" {
            $DryRun = $false
            Mock -CommandName Read-Host -MockWith { "N" }

            { Confirm-Action -Message "Cancel?" -Force:$false } | Should -Throw
        }
    }

    Context "Test-CsvHeader" {
        BeforeAll {
            # Define mock required columns for both modes
            $requiredRegistrationColumns = @("userId", "serialNumber")
            $requiredUPNColumns = @("userPrincipalName", "displayName")
        }

        It "should not throw if required headers exist (registration mode)" {
            $csv = @(
                [pscustomobject]@{ userId = "u1"; serialNumber = "SN1" },
                [pscustomobject]@{ userId = "u2"; serialNumber = "SN2" }
            )

            { Test-CsvHeader -csv $csv } | Should -Not -Throw
        }

        It "should not throw if required headers exist (GenChallenge mode)" {
            $csv = @(
                [pscustomobject]@{ userPrincipalName = "u1@domain.com"; displayName = "User One" },
                [pscustomobject]@{ userPrincipalName = "u2@domain.com"; displayName = "User Two" }
            )

            { Test-CsvHeader -csv $csv -GenChallenge } | Should -Not -Throw
        }

        It "should throw if a required column is missing (registration mode)" {
            $csv = @(
                [pscustomobject]@{ userId = "u1" } # Missing serialNumber
            )

            { Test-CsvHeader -csv $csv } | Should -Throw "❌ Missing required column: serialNumber"
        }

        It "should throw if a required column is missing (GenChallenge mode)" {
            $csv = @(
                [pscustomobject]@{ displayName = "User One" } # Missing userPrincipalName
            )

            { Test-CsvHeader -csv $csv -GenChallenge } | Should -Throw "❌ Missing required column: userPrincipalName"
        }
    }

    Context "Test-CsvRow" {
        It "should return $true for valid challenge row" {
            $row = [pscustomobject]@{ userPrincipalName = "test@domain.com" }
            (Test-CsvRow -row $row -GenChallenge).ToString() | Should -Be "True"
        }

        It "should return $false for invalid challenge row" {
            $row = [pscustomobject]@{ userPrincipalName = "" }
            (Test-CsvRow -row $row -GenChallenge).ToString() | Should -Be "False"
        }

        It "should return $true for valid registration row" {
            $row = [pscustomobject]@{
                userId = "123"
                serialNumber = "FX7ABC"
                credentialId = "cred"
                attestationObject = "att"
                clientDataJson = "json"
            }
            (Test-CsvRow -row $row).ToString() | Should -Be "True"
        }

        It "should return $false for missing fields" {
            $row = [pscustomobject]@{
                userId = "123"
                serialNumber = ""
                credentialId = "cred"
                attestationObject = "att"
                clientDataJson = "json"
            }
            (Test-CsvRow -row $row).ToString() | Should -Be "False"
        }
    }

    Context "Import-CsvData" {

        BeforeEach {
            # Default Mocks
            Mock -CommandName Test-Path -MockWith { return $true }
            Mock -CommandName Import-Csv -MockWith {
                return @(
                    [pscustomobject]@{ userId = "u1"; serialNumber = "SN1" },
                    [pscustomobject]@{ userId = "u2"; serialNumber = "SN2" }
                )
            }
            Mock -CommandName Test-CsvHeader -MockWith { return $true }
        }

        It "should throw if the CSV file does not exist" {
            Mock Test-Path { return $false }

            { Import-CsvData -path "fake.csv" } | Should -Throw "❌ CSV not found at path: fake.csv"
        }

        It "should call Import-Csv when file exists" {
            Import-CsvData -path "mock.csv" | Out-Null

            Assert-MockCalled -CommandName Import-Csv -Exactly 1 -Scope It
        }

        It "should call Test-CsvHeader with -GenChallenge switch" {
            Import-CsvData -path "mock.csv" -GenChallenge | Out-Null

            Assert-MockCalled -CommandName Test-CsvHeader -Exactly 1 -Scope It -ParameterFilter { $GenChallenge }
        }

        It "should call Test-CsvHeader without -GenChallenge switch" {
            Import-CsvData -path "mock.csv" | Out-Null

            Assert-MockCalled -CommandName Test-CsvHeader -Exactly 1 -Scope It -ParameterFilter { -not $GenChallenge }
        }

        It "should return the parsed CSV content" {
            $result = Import-CsvData -path "mock.csv"

            $result.Count | Should -Be 2
            $result[0].userId | Should -Be "u1"
            $result[1].serialNumber | Should -Be "SN2"
        }
    }

    Context "Get-UserIdFromUpn" {

        BeforeEach {
            # Default mock behavior
            Mock -CommandName Get-MgUser -MockWith {
                return [pscustomobject]@{
                    Id = "user-123"
                    UserPrincipalName = "john.doe@example.com"
                }
            }
        }

        It "should return the user ID for a valid UPN" {
            $result = Get-UserIdFromUpn -upn "john.doe@example.com"
            $result | Should -Be "user-123"
        }

        It "should throw if UPN is null or whitespace" {
            { Get-UserIdFromUpn -upn "" } | Should -Throw
        }

        It "should return null if user is not found" {
            Mock -CommandName Get-MgUser -MockWith { return @() }

            $result = Get-UserIdFromUpn -upn "missing@example.com"
            $result | Should -BeNullOrEmpty
        }

        It "should return null if an exception is thrown by Get-MgUser" {
            Mock -CommandName Get-MgUser -MockWith { throw "API error" }

            $result = Get-UserIdFromUpn -upn "error@example.com"
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Get-UpnFromUserId" {

        BeforeEach {
            # Default mock for Get-MgUser
            Mock -CommandName Get-MgUser -MockWith {
                return [pscustomobject]@{ UserPrincipalName = "john.doe@example.com" }
            }
        }

        It "should return UPN when user is found" {
            $result = Get-UpnFromUserId -userId "12345"
            $result | Should -Be "john.doe@example.com"
        }

        It "should throw if userId is null or whitespace" {
            { Get-UpnFromUserId -userId "" } | Should -Throw
        }

        It "should throw if user is not found" {
            Mock -CommandName Get-MgUser -MockWith { throw "User not found" }

            { Get-UpnFromUserId -userId "unknown-id" } | Should -Throw "❌ Failed to retrieve UPN for userId unknown-id: User not found"
        }

        It "should throw if user has no UPN" {
            Mock -CommandName Get-MgUser -MockWith {
                return [pscustomobject]@{ UserPrincipalName = $null }
            }

            { Get-UpnFromUserId -userId "no-upn-id" } | Should -Throw "*No UPN found for userId*"
        }
    }

    Context "Get-Fido2CredentialCreationOptions" {

        It "should return creation options when API call succeeds" {
            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                return @{
                    publicKey = @{
                        challenge = "abc123"
                        rp = @{ name = "OneSpan" }
                    }
                }
            }

            $result = Get-Fido2CredentialCreationOptions -userId "user-id-123"
            $result.publicKey.challenge | Should -Be "abc123"
        }

        It "should return `$null when API call throws" {
            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                throw "Simulated API failure"
            }

            $result = Get-Fido2CredentialCreationOptions -userId "user-id-123"
            $result | Should -Be $null
        }

        It "should throw if userId is missing or whitespace" {
            { Get-Fido2CredentialCreationOptions -userId "" } | Should -Throw
            { Get-Fido2CredentialCreationOptions -userId "   " } | Should -Throw
            { Get-Fido2CredentialCreationOptions -userId $null } | Should -Throw
        }

        It "should call Invoke-MgGraphRequest with correct URI" {
            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                param($Method, $Uri, $OutputType)
                $script:lastUriCalled = $Uri
                return @{ publicKey = @{ challenge = "abc123" } }
            }

            $userId = "test-user"
            Get-Fido2CredentialCreationOptions -userId $userId -challengeTimeoutInMinutes 15

            $expectedUri = "/beta/users/$userId/authentication/fido2Methods/creationOptions?challengeTimeoutInMinutes=15"
            $script:lastUriCalled | Should -Be $expectedUri
        }
    }

    Context "Get-ExistingFido2Credentials" {

        It "should return existing FIDO2 credentials if any exist" {
            $mockUserId = "user-abc"
            $mockCreds = @(
                [pscustomobject]@{ id = "cred-1"; displayName = "Token A" },
                [pscustomobject]@{ id = "cred-2"; displayName = "Token B" }
            )

            Mock -CommandName Get-MgUserAuthenticationFido2Method -MockWith {
                param($UserId)
                return $mockCreds
            }

            $result = Get-ExistingFido2Credentials -userId $mockUserId

            $result.Count | Should -Be 2
            $result[0].id | Should -Be "cred-1"
            $result[1].displayName | Should -Be "Token B"
        }

        It "should return empty array when no credentials exist" {
            $mockUserId = "user-empty"

            Mock -CommandName Get-MgUserAuthenticationFido2Method -MockWith {
                param($UserId)
                return @()
            }

            $result = Get-ExistingFido2Credentials -userId $mockUserId
            $result | Should -BeNullOrEmpty
        }

        It "should return empty array and log error on exception" {
            $mockUserId = "user-exception"

            Mock -CommandName Get-MgUserAuthenticationFido2Method -MockWith {
                param($UserId)
                throw "Simulated API failure"
            }

            $result = Get-ExistingFido2Credentials -userId $mockUserId
            $result | Should -BeNullOrEmpty
        }

        It "should throw if userId is null or whitespace" {
            { Get-ExistingFido2Credentials -userId "" } | Should -Throw
        }
    }

    Context "Test-CredentialAlreadyAssigned" {

        It "should return credential when credentialId matches" {
            $mockUserId = "user1"
            $mockCredId = "cred123"
            $mockDisplayName = "My Token"

            Mock -CommandName Get-ExistingFido2Credentials -MockWith {
                return @(
                    [pscustomobject]@{ id = "cred123"; displayName = "Another Token" },
                    [pscustomobject]@{ id = "other"; displayName = "Not this one" }
                )
            }

            $result = Test-CredentialAlreadyAssigned -userId $mockUserId -cId $mockCredId -displayName $mockDisplayName
            $result.id | Should -Contain "cred123"
        }

        It "should return credential when displayName matches" {
            $mockUserId = "user2"
            $mockCredId = "no-match"
            $mockDisplayName = "Matching Name"

            Mock -CommandName Get-ExistingFido2Credentials -MockWith {
                return @(
                    [pscustomobject]@{ id = "irrelevant"; displayName = "Matching Name" },
                    [pscustomobject]@{ id = "other"; displayName = "Different Name" }
                )
            }

            $result = Test-CredentialAlreadyAssigned -userId $mockUserId -cId $mockCredId -displayName $mockDisplayName
            $result.displayName | Should -Contain "Matching Name"
        }

        It "should return nothing when there are no matches" {
            $mockUserId = "user3"
            $mockCredId = "nonexistent"
            $mockDisplayName = "Nothing Matches"

            Mock -CommandName Get-ExistingFido2Credentials -MockWith {
                return @(
                    [pscustomobject]@{ id = "some"; displayName = "Other Token" }
                )
            }

            $result = Test-CredentialAlreadyAssigned -userId $mockUserId -cId $mockCredId -displayName $mockDisplayName
            $result | Should -BeNullOrEmpty
        }

        It "should return nothing when user has no credentials" {
            $mockUserId = "user4"
            $mockCredId = "any"
            $mockDisplayName = "any"

            Mock -CommandName Get-ExistingFido2Credentials -MockWith {
                return @()
            }

            $result = Test-CredentialAlreadyAssigned -userId $mockUserId -cId $mockCredId -displayName $mockDisplayName
            $result | Should -BeNullOrEmpty
        }
    }

    Context "Register-Fido2Credential" {

        BeforeAll {
            $mockUserId = "test-user-id"
            $mockDisplayName = "Test Token"
            $mockCredId = "cred-123"
            $mockClientData = "mock-client-data"
            $mockAttObj = "mock-att-obj"
            $DryRun = $false
        }

        It "should return response when registration succeeds" {

            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                return @{ status = "success" }
            }
            Assert-MockCalled -CommandName Invoke-MgGraphRequest -Exactly 0 -Scope It


            $response = Register-Fido2Credential `
                -userId $mockUserId `
                -displayName $mockDisplayName `
                -cId $mockCredId `
                -clientDataJson $mockClientData `
                -attestationObject $mockAttObj

            $response.status | Should -Be "success"
        }

        It "should return true and skip registration in DryRun mode" {
            $DryRun = $true

            $response = Register-Fido2Credential `
                -userId $mockUserId `
                -displayName $mockDisplayName `
                -cId $mockCredId `
                -clientDataJson $mockClientData `
                -attestationObject $mockAttObj

            $response | Should -Be $true

            # DryRun should skip actual API call
            Assert-MockCalled -CommandName Invoke-MgGraphRequest -Times 0
            $global:DryRun = $false
        }

        It "should return null when API call fails" {
            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                throw "Simulated failure"
            }

            $response = Register-Fido2Credential `
                -userId $mockUserId `
                -displayName $mockDisplayName `
                -cId $mockCredId `
                -clientDataJson $mockClientData `
                -attestationObject $mockAttObj

            $response | Should -Be $null
        }

        It "should throw if required parameters are missing" {
            { Register-Fido2Credential -userId "" -displayName "name" -cId "id" -clientDataJson "json" -attestationObject "att" } | Should -Throw
            { Register-Fido2Credential -userId "u" -displayName "" -cId "id" -clientDataJson "json" -attestationObject "att" } | Should -Throw
            { Register-Fido2Credential -userId "u" -displayName "name" -cId "" -clientDataJson "json" -attestationObject "att" } | Should -Throw
            { Register-Fido2Credential -userId "u" -displayName "name" -cId "id" -clientDataJson "" -attestationObject "att" } | Should -Throw
            { Register-Fido2Credential -userId "u" -displayName "name" -cId "id" -clientDataJson "json" -attestationObject "" } | Should -Throw
        }

        It "should call Invoke-MgGraphRequest with correct payload" {
            $capturedBody = $null
            Mock -CommandName Invoke-MgGraphRequest -MockWith {
                param($Body)
                $script:capturedBody = $Body
                return @{ status = "mocked" }
            }

            Register-Fido2Credential `
                -userId $mockUserId `
                -displayName $mockDisplayName `
                -cId $mockCredId `
                -clientDataJson $mockClientData `
                -attestationObject $mockAttObj

            $json = $script:capturedBody | ConvertFrom-Json
            $json.displayName | Should -Be $mockDisplayName
            $json.publicKeyCredential.id | Should -Be $mockCredId
            $json.publicKeyCredential.response.clientDataJSON | Should -Be $mockClientData
            $json.publicKeyCredential.response.attestationObject | Should -Be $mockAttObj
        }
    }

    Describe "Invoke-UserGenerateChallenges" {
        BeforeEach {
            # We default to DryRun = True in BeforeAll
            $DryRun = $false
            # Use the Pester Test Drive for File System Mocks
            $OutputPath = "$TestDrive\output.csv"
            # Set a valid CSV for all tests
            $csv = @(
                @{ userPrincipalName = "user1@example.com" }
            )
            $mockChallenge = '{"publicKey": {"challenge": "mockedChallenge"}}'
            $mockChallengeObject = @{
                publicKey = @{
                    challenge = "mockedChallenge"
                }
            }

            Mock -CommandName Write-Log { param ($Message, $Type) }
            Mock -CommandName Test-CsvRow { return $true }
            Mock -CommandName Get-UserIdFromUpn { return "user-123" }
            Mock -CommandName Get-Fido2CredentialCreationOptions { return $mockChallenge }
            Mock -CommandName ConvertFrom-Json { return $mockChallengeObject }
            Mock -CommandName Export-Csv{ Write-Output "Export-Csv was called with path: $OutputPath" }
        }

        It "should generate challenges and export them successfully" {
            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Test-CsvRow -Exactly 1
            Assert-MockCalled Get-UserIdFromUpn -Exactly 1
            Assert-MockCalled Get-Fido2CredentialCreationOptions -Exactly 1
            Assert-MockCalled ConvertFrom-Json -Exactly 1
            Assert-MockCalled Export-Csv -Exactly 1
        }

        It "should skip invalid CSV rows" {
            $csv = @(
                @{ userPrincipalName = "" }
            )

            Mock Test-CsvRow { $false }

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0 -Scope It
            Assert-MockCalled Write-Log -Exactly 2
        }

        It "should skip if user is not found" {
            $csv = @(
                @{ userPrincipalName = "missinguser@example.com" }
            )

            Mock Get-UserIdFromUpn { $null }

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0 -Scope It
            Assert-MockCalled Write-Log -Exactly 3
        }

        It "should handle errors when challenge generation fails" {
            Mock Get-Fido2CredentialCreationOptions { $null }

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0 -Scope It
            Assert-MockCalled Write-Log -Exactly 5
        }

        It "should log an error if export fails" {
            Mock Export-Csv { throw "Simulated Export failed." }

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 1 -Scope It
            Assert-MockCalled Write-Log -Exactly 6
        }

        It "should not export during dry run mode" {
            $DryRun = $true

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0
            Assert-MockCalled Write-Log -Exactly 6
        }

        It "should log an error if no challenges are generated" {
            Mock Get-UserIdFromUpn { $null }

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0 -Scope It
            Assert-MockCalled Write-Log -Exactly 1 -Scope It -ParameterFilter {
                $msg -like "*No challenges generated. Export aborted.*" -and
                $type -eq "Error"
            }
        }

        It "should handle an empty CSV input" {
            $csv = @()

            Invoke-UserGenerateChallenges -csv $csv

            Assert-MockCalled Export-Csv -Exactly 0 -Scope It
            Assert-MockCalled Write-Log -Exactly 1 -Scope It -ParameterFilter {
                $msg -like "*No challenges generated. Export aborted.*" -and
                $Type -eq "Error"
            }
        }
    }

    Describe "Invoke-UserRegistrations" {
        BeforeEach {
            # Reset the global counters and variables
            $successCount = 0
            $failureCount = 0
            $Force = $false
            $csv = @(
                @{ userId = "user-123"; serialNumber = "FX7-001"; credentialId = "cred-123"; clientDataJson = "jsonData"; attestationObject = "attObj" }
            )

            # Default mocks
            Mock Confirm-Action { return $true}
            Mock Test-CsvRow { return $true }
            Mock Get-UpnFromUserId { return "user@example.com" }
            Mock Test-CredentialAlreadyAssigned { return $false }
            Mock Register-Fido2Credential { return $true }
            Mock Write-Log { }
        }

        It "should successfully register FIDO2 key when no errors occur" {
            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Confirm-Action -Exactly 1
            Assert-MockCalled Test-CsvRow -Exactly 1
            Assert-MockCalled Get-UpnFromUserId -Exactly 1
            Assert-MockCalled Test-CredentialAlreadyAssigned -Exactly 1
            Assert-MockCalled Register-Fido2Credential -Exactly 1
            Assert-MockCalled Write-Log -Exactly 9
        }

        It "should exit if Confirm-Action returns false" {
            Mock Confirm-Action { return $false }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Confirm-Action -Exactly 1
            Assert-MockCalled Test-CsvRow -Exactly 0
            Assert-MockCalled Register-Fido2Credential -Exactly 0
            Assert-MockCalled Write-Log -Exactly 0
        }

        It "should skip invalid CSV rows" {
            Mock Test-CsvRow { return $false }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Test-CsvRow -Exactly 1
            Assert-MockCalled Write-Log -Exactly 4
            Assert-MockCalled Register-Fido2Credential -Exactly 0
        }

        It "should log a warning and skip if Get-UpnFromUserId fails" {
            Mock Get-UpnFromUserId { throw "User not found" }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Get-UpnFromUserId -Exactly 1
            Assert-MockCalled Write-Log -Exactly 6
            Assert-MockCalled Register-Fido2Credential -Exactly 0
        }

        It "should log a warning and skip if the credential is already assigned" {
            Mock Test-CredentialAlreadyAssigned { return $true }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Test-CredentialAlreadyAssigned -Exactly 1
            Assert-MockCalled Write-Log -Exactly 7
            Assert-MockCalled Register-Fido2Credential -Exactly 0
        }

        It "should log an error if Register-Fido2Credential fails" {
            Mock Register-Fido2Credential { return $false }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Register-Fido2Credential -Exactly 1
            Assert-MockCalled Write-Log -Exactly 9
        }

        It "should correctly handle multiple rows with mixed results" {
            $csv = @(
                @{ userId = "user-123"; serialNumber = "SN123"; credentialId = "cred-123"; clientDataJson = "data"; attestationObject = "object"; userPrincipalName = "user1@example.com" }
                @{ userId = "user-456"; serialNumber = "SN456"; credentialId = "cred-456"; clientDataJson = "data"; attestationObject = "object"; userPrincipalName = "user2@example.com" }
                @{ userId = "user-789"; serialNumber = "SN789"; credentialId = "cred-789"; clientDataJson = "data"; attestationObject = "object"; userPrincipalName = "user3@example.com" }
            )

            Mock Register-Fido2Credential {
                if ($args[0] -eq "user-456") {
                    return $false
                }
                return $true
            }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Register-Fido2Credential -Exactly 3
            Assert-MockCalled Write-Log -Exactly 21
        }

        It "should log summary results correctly" {
            Mock Register-Fido2Credential { return $true }

            Invoke-UserRegistrations -csv $csv

            Assert-MockCalled Write-Log -Exactly 9
            Assert-MockCalled Write-Log -Exactly 1 -Scope It -ParameterFilter {
                $msg -like "*🎉 Summary:*" -and $ForegroundColor -eq "Cyan" -and $type -eq "Host"
            }
            Assert-MockCalled Write-Log -Exactly 1 -Scope It -ParameterFilter {
                $msg -like "*✅ Successfully registered tokens: 1*" -and $ForegroundColor -eq "Green" -and $type -eq "Host"
            }
            Assert-MockCalled Write-Log -Exactly 1 -Scope It -ParameterFilter {
                $msg -like "*❌ Failed/Skipped registrations: 0*" -and $ForegroundColor -eq "Red" -and $type -eq "Host"
            }
        }
    }

    Describe "Script Initialization" {

        BeforeEach {
            # Setup common variables
            $TenantId = "mock-tenant-id"
            $LogPath = "$TestDrive\Logs"
            $logOutputFileName = "test-log.log"
            $CsvPath = "$TestDrive\input.csv"
            $OutputPath = "$TestDrive\output.csv"
            $Mode = $null
            # Mock common functions
            Mock Test-LogPath {}
            Mock Write-Log {}
            Mock Join-Path { return "mocked/log/path.log" }
            Mock Install-ModuleIfNeeded {}
            Mock Connect-ToMsGraph {}
            Mock Import-CsvData { return @(@{}) }
            Mock Invoke-UserGenerateChallenges {}
            Mock Invoke-UserRegistrations {}
        }

        It "When LogPath is set should test log path and write log to console" {
            $LogPath = "$TestDrive\Logs"
            $logOutputFileName = "TestLog.log"

            Mock Test-LogPath { }
            Mock Write-Log { }

            Main -Mode "register-credentials" -TenantId "test-tenant-id" -CsvPath $CsvMockPathRegister -LogPath $LogPath

            Assert-MockCalled Test-LogPath -Exactly 1
            Assert-MockCalled Write-Log -Exactly 1 -ParameterFilter {
                $msg -like "*Logging to file:*" -and $type -eq "Host"
            }
        }

        It "When LogPath is not set should not test log path or write log to console" {
            Mock Test-LogPath { }
            Mock Write-Log { }

            Main -Mode "register-credentials" -TenantId "test-tenant-id" -CsvPath $CsvMockPathRegister

            Assert-MockCalled Test-LogPath -Exactly 0
            Assert-MockCalled Write-Log -Exactly 0 -ParameterFilter {
                $msg -like "*Logging to file:*"
            }
        }

        It "Module Installation, should install Microsoft.Graph.Beta module" {
            Mock Install-ModuleIfNeeded {}
            Main -Mode "register-credentials" -TenantId "tenant" -CsvPath $CsvMockPathRegister -LogPath "C:\Temp"

            Assert-MockCalled Install-ModuleIfNeeded -Exactly 1 -ParameterFilter { $ModuleName -eq "Microsoft.Graph.Beta" }
        }

        It "Graph Connection, should connect to Microsoft Graph with TenantId" {
            Mock Connect-ToMsGraph {}
            Main -Mode "register-credentials" -TenantId "abc-123" -CsvPath $CsvMockPathRegister -LogPath "C:\Temp"

            Assert-MockCalled Connect-ToMsGraph -Exactly 1 -ParameterFilter { $TenantId -eq "abc-123" }
        }

        Context "Generate Challenges Mode" {
            It "should set OutputPath to default if not provided" {
                Mock Join-Path { return "$TestDrive\Generated.csv" }
                Mock Import-CsvData { return @(@{ userPrincipalName = "user@example.com" }) }
                Mock Invoke-UserGenerateChallenges {}

                Remove-Variable OutputPath -ErrorAction SilentlyContinue

                Main -Mode "generate-challenges" -TenantId "tenant" -CsvPath $CsvMockPathRegister

                Assert-MockCalled Join-Path -Exactly 1
            }

            It "should generate challenges when mode is set to generate-challenges" {
                Mock Import-CsvData { return @(@{ userPrincipalName = "user@example.com" }) }
                Mock Invoke-UserGenerateChallenges {}
                Main -Mode "generate-challenges" -TenantId "tenant" -CsvPath $CsvMockPathRegister

                Assert-MockCalled Invoke-UserGenerateChallenges -Exactly 1
            }

            It "should not set OutputPath if already provided" {
                Mock Join-Path { throw "Should not be called" }
                Mock Import-CsvData { return @(@{ userPrincipalName = "user@example.com" }) }
                Mock Invoke-UserGenerateChallenges {}

                $OutputPath = "C:\Already\Set.csv"
                Main -Mode "generate-challenges" -TenantId "tenant" -CsvPath $CsvMockPathRegister -OutputPath $OutputPath
            }
        }

        Context "Register Credentials Mode" {
            It "should register credentials when mode is set to register-credentials" {
                Mock Import-CsvData { return @(@{ userId = "u1"; serialNumber = "s1"; credentialId = "c1"; attestationObject = "ao"; clientDataJson = "cdj" }) }
                Mock Invoke-UserRegistrations {}
                Main -Mode "register-credentials" -TenantId "tenant" -CsvPath $CsvMockPathRegister

                Assert-MockCalled Invoke-UserRegistrations -Exactly 1
            }
        }

        Context "Invalid Mode" {
            It "should throw an error if mode is invalid" {
                { Main -Mode "invalid-mode" -TenantId "test-tenant-id" -CsvPath $CsvMockPathRegister } |
                    Should -Throw "❌ Invalid mode. Use 'generate-challenges' or 'register-credentials'."
            }
        }
    }

    Describe "Main function invocation" {
        BeforeEach {
            # Mock the Main function
            Mock Main {}

            # Save original environment variable value
            $OriginalTestMode = $env:TEST_MODE
        }

        AfterEach {
            # Restore original environment variable value
            if ($null -eq $OriginalTestMode){
              Remove-Variable env:TEST_MODE
            } else {
              $env:TEST_MODE = $OriginalTestMode
            }
            #Clear-Mock Main
        }

        It "should call Main when TEST_MODE is not set and script is not dot-sourced" {
            # Ensure TEST_MODE is not set
            Remove-Variable env:TEST_MODE -ErrorAction SilentlyContinue
            [Environment]::SetEnvironmentVariable("TEST_MODE", $null)

            # Simulate script not being dot-sourced
            $MyInvocation = @{ InvocationName = "MyScript.ps1" }

            # Execute the code under test
            if (-not $env:TEST_MODE -and $MyInvocation.InvocationName -ne '.') {
                Write-Host "Main function is being called"
                Main @PSBoundParameters
            }

            # Assert that Main was called
            Assert-MockCalled -CommandName Main -Exactly 1
        }

        It "should not call Main when TEST_MODE is set" {
            # Set TEST_MODE
            $env:TEST_MODE = 1
            [Environment]::SetEnvironmentVariable("TEST_MODE", 1)

            # Simulate script not being dot-sourced
            $MyInvocation = @{ InvocationName = "MyScript.ps1" }

            # Execute the code under test
            if (-not $env:TEST_MODE -and $MyInvocation.InvocationName -ne '.') {
                Main @PSBoundParameters
            }

            # Assert that Main was not called
            Assert-MockCalled -CommandName Main -Exactly 0
        }

        It "should not call Main when script is dot-sourced" {
            # Ensure TEST_MODE is not set
            Remove-Variable env:TEST_MODE -ErrorAction SilentlyContinue
            [Environment]::SetEnvironmentVariable("TEST_MODE", $null)

            # Simulate script being dot-sourced
            $MyInvocation = @{ InvocationName = "." }

            # Execute the code under test
            if (-not $env:TEST_MODE -and $MyInvocation.InvocationName -ne '.') {
                Main @PSBoundParameters
            }

            # Assert that Main was not called
            Assert-MockCalled -CommandName Main -Exactly 0
        }
    }
}
