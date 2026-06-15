# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.3.0] - 2026-06-15

### Added

- **GitHub Actions CI workflow** (`.github/workflows/pester.yml`):
  - Triggers on every push to `main` and on every pull request targeting `main`.
  - Runs on `windows-latest` using Windows PowerShell 5.1, matching the script's minimum requirement.
  - Installs Pester ≥ 5.0 from PSGallery before each run.
  - Executes the full test suite via `New-PesterConfiguration` (the Pester v5 recommended approach — not the deprecated `-CodeCoverage` parameter flag).
  - Generates a **JaCoCo** `coverage/coverage.xml` scoped to the production script.
  - Generates a **JUnit XML** `test-results.xml` for test result publishing.
  - Publishes test results to the **Checks tab** via `dorny/test-reporter@v1` (pass/fail visible inline on the PR).
  - Parses JaCoCo coverage and writes a **markdown summary** to the job summary page via `irongut/CodeCoverageSummary@v1.3.0`.
    - Warning threshold: 70 %, failure threshold: 90 %.
  - Posts a **sticky PR comment** with the coverage table via `marocchino/sticky-pull-request-comment@v2` (updates in place on each new push, visible without navigating away from the PR).
  - Uploads `coverage/coverage.xml` and `test-results.xml` as a workflow artifact retained for 30 days.

- **`.gitignore`**: added `test-results.xml` and `code-coverage-results.md` so CI-generated artifacts are never accidentally committed.

---

## [1.2.0] - 2026-06-15

### Fixed

- **OData filter injection** in `Get-UserIdFromUpn`: UPNs containing a single quote (e.g. `o'reilly@example.com`)
  previously produced a malformed OData filter (`userPrincipalName eq 'o'reilly@example.com'`).
  Single quotes are now escaped as `''` before the filter string is constructed.

- **Silent null challenge export** in `Invoke-UserGenerateChallenges`: when the Graph API returned a response
  whose `publicKey.challenge` field was `null` or absent, a row with a null challenge was silently written to
  the output CSV. The script now logs a warning and skips that row.

### Added

- **`Test-CsvDataQuality` function**: called automatically after `Confirm-Action` in `Invoke-UserRegistrations`.
  Before any API calls are made, it scans the CSV for duplicate `credentialId` and `serialNumber` values and
  logs a warning for each one found. Processing continues so individual rows are still attempted; duplicates
  will be caught at the credential level by `Test-CredentialAlreadyAssigned`.

### Tests

- **`Test-CsvRow`**: added two tests verifying that whitespace-only values (e.g. `"   "`) are correctly
  rejected by `IsNullOrWhiteSpace` for both registration and challenge rows.

- **`Context "Test-CsvDataQuality"`** (6 new tests): duplicate `credentialId`, duplicate `serialNumber`,
  both duplicates in the same CSV, single-row CSV, clean-data pass message, and a multi-duplicate warning count.

- **`Get-UserIdFromUpn`**: regression test that verifies a UPN containing a single quote produces an OData
  filter with the quote properly doubled (`o''reilly@example.com`).

- **`Invoke-UserGenerateChallenges`**: test that verifies a null `challenge` in the parsed Graph response
  logs a warning and skips the row rather than exporting a null value.

- **`Invoke-UserRegistrations`** (3 new tests):
  - Data quality check fires after confirmation and before the processing loop.
  - Duplicate `credentialId` rows warn but processing continues.
  - Data quality check is skipped when `Confirm-Action` returns false.

---

## [1.1.0] - 2026-06-15

### Changed

- **Module dependency** replaced `Microsoft.Graph.Beta` with `Microsoft.Graph.Identity.SignIns` (MinimumVersion `2.26.0`).
  The GA module is now preferred over the Beta module, which is consistent with the stable v1.0 Graph API endpoints used in this script.

- **`Install-ModuleIfNeeded`** now accepts an optional `-MinimumVersion` parameter.
  - If the module is already installed at or above the requested minimum version, installation is skipped.
  - If the installed version is below the minimum, the module is (re-)installed.
  - `-MinimumVersion` is forwarded to both `Install-Module` (PS 5.x) and `Install-PSResource` (PS 7+).

- **`Register-Fido2Credential`** — fixed HTTP 400 BadRequest regression introduced by `Microsoft.Graph.Authentication` SDK 2.26+.
  In SDK 2.26 and above, passing a `[string]` to `Invoke-MgGraphRequest -Body` causes the SDK to re-serialize the value,
  wrapping it in a JSON string literal so the server receives a quoted string at the document root instead of a JSON object.
  The body is now encoded as `[byte[]]` (`UTF-8`) before being passed to `Invoke-MgGraphRequest`, which bypasses
  SDK serialization entirely and sends the raw JSON as-is.

- **Graph API URIs** updated from `/beta/` to `/v1.0/` for both endpoints:
  - `GET /v1.0/users/{userId}/authentication/fido2Methods/creationOptions`
  - `POST /v1.0/users/{userId}/authentication/fido2Methods`

### Fixed

- HTTP 400 BadRequest (`"The request is missing a fido2AuthenticationMethod entity"`) when registering FIDO2 credentials
  against tenants using `Microsoft.Graph.Identity.SignIns` 2.26.0+.

### Tests

- **`Install-ModuleIfNeeded`** — 4 new test cases:
  - Installed version below `MinimumVersion` → triggers reinstall.
  - Installed version meets `MinimumVersion` → skips install.
  - `MinimumVersion` forwarded correctly via `Install-Module` on PS 5.x.
  - `MinimumVersion` forwarded correctly via `Install-PSResource` on PS 7+ (skipped on PS 5.1).
  - `Get-Module` mock updated to include a `Version` property so version comparisons work correctly.
  - `BeforeEach` now creates a `script:Install-PSResource` stub when running on PS 5.1 (where the command does not ship),
    allowing Pester to mock it without a `CommandNotFoundException`.

- **`Get-Fido2CredentialCreationOptions`** URI assertion updated to expect `/v1.0/` instead of `/beta/`.

- **`Register-Fido2Credential`** payload assertion updated:
  - Verifies the captured body is `[byte[]]` using `-is [byte[]]` (avoids Pester pipeline unrolling).
  - Decodes the bytes via `[System.Text.Encoding]::UTF8.GetString()` before deserializing with `ConvertFrom-Json`.

- **`Script Initialization`** module-installation test updated to assert `Microsoft.Graph.Identity.SignIns` with
  `MinimumVersion "2.26.0"` instead of `Microsoft.Graph.Beta`.

---

## [1.0.0] - Initial release

- Challenge generation mode (`generate-challenges`): reads UPNs from CSV, requests FIDO2 creation options from Graph, exports a challenge CSV for OneSpan.
- Credential registration mode (`register-credentials`): reads a credential CSV from OneSpan, validates columns, checks for existing assignments, and registers FIDO2 keys via Graph.
- Supports `DryRun`, `Force`, `VerboseLogging`, and `LogPath` parameters.
- Compatible with PowerShell 5.1 and 7+.
- Full Pester unit test suite with ≥ 99% code coverage.
