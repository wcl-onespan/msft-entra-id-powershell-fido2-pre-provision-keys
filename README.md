# Entra ID FIDO2 Pre-Provisioning Script

![Pester Tests](https://github.com/wcl-onespan/msft-entra-id-powershell-fido2-pre-provision-keys/actions/workflows/pester.yml/badge.svg)

This PowerShell script enables automated **FIDO2 credential management** for Microsoft Entra ID (Azure AD) users via the Microsoft Graph API. It supports both:

- ✅ Generating **FIDO2 credential challenges** for OneSpan pre-provisioning
- ✅ Registering **pre-provisioned FIDO2 keys** into Microsoft Entra ID

---

## 📂 Project Structure

```
.
├── .github/
│   └── workflows/
│       └── pester.yml                               # 🔄 GitHub Actions CI (tests + coverage)
├── entra-id-pre-provision-keys-onespan-fx7.ps1      # ✅ Main script
├── tests/
│   ├── entra-id-pre-provision-keys-onespan-fx7.Tests.ps1  # ✅ Unit tests
│   └── temp-test-data.csv                          # 🧪 CSV used in testing
├── coverage/
│   └── coverage.xml                                 # 📊 Pester code coverage report
├── .vscode/
│   └── settings.json                                # ⚙️ VSCode test + coverage settings
└── README.md                                        # 📘 This file
```

---

## 🚀 Features

- Supports `generate-challenges` and `register-credentials` modes
- Uses Microsoft Graph v1.0 API (`Microsoft.Graph.Identity.SignIns` ≥ 2.26)
- Fully compatible with **PowerShell 5.1 and 7+**
- Modular functions with high testability
- Built-in logging, dry-run support, and force override
- Built-in CSV data quality pre-flight check (duplicate credential/serial detection)
- ⚡ 98 unit tests, 0 failures
- 🔄 GitHub Actions CI with test results and coverage comment on every PR

---

## 🛠️ Requirements

- PowerShell 5.1 or 7+
- [`Microsoft.Graph.Identity.SignIns`](https://www.powershellgallery.com/packages/Microsoft.Graph.Identity.SignIns) ≥ 2.26.0
- Pester (for testing)

---

## 🧪 Running Unit Tests

Run all unit tests using Pester:

```powershell
$env:TEST_MODE = "1"
Invoke-Pester -Path .\tests -Output Detailed
```

To also generate a local coverage report:

```powershell
$env:TEST_MODE = "1"
$config = New-PesterConfiguration
$config.Run.Path = ".\tests"
$config.CodeCoverage.Enabled = $true
$config.CodeCoverage.Path = ".\entra-id-pre-provision-keys-onespan-fx7.ps1"
$config.CodeCoverage.OutputFormat = "JaCoCo"
$config.CodeCoverage.OutputPath = ".\coverage\coverage.xml"
Invoke-Pester -Configuration $config
```

💡 **Code coverage** is tracked in `./coverage/coverage.xml` (JaCoCo format). In VS Code, live gutter highlighting is provided by the [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters) extension — see the `.vscode/settings.json` configuration below.

---

## 🔄 Continuous Integration

Every pull request and push to `main` runs the full test suite via GitHub Actions (`.github/workflows/pester.yml`):

- ✅ Test pass/fail results appear in the **Checks** tab on the PR
- 📊 A **coverage table** is posted as a sticky PR comment and written to the job summary
- 📦 `coverage/coverage.xml` and `test-results.xml` are uploaded as workflow artifacts (retained 30 days)
- 🚫 The workflow fails if line coverage drops below 90 % (warning below 70 %)

> **First-time setup:** replace `<org>/<repo>` in the README badge URL with your actual GitHub repository path.

---

## 🧬 VSCode Integration

If you're using VSCode, this project includes built-in coverage and Pester support via the `.vscode/settings.json` file:

```json
{
  "powershell.pester.codeLens": false,
  "coverage-gutters.coverageFileNames": [
    "coverage/coverage.xml"
  ],
  "coverage-gutters.coverageBaseDir": "${workspaceFolder}"
}
```

✅ This enables live coverage highlighting with the [Coverage Gutters](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters) extension.

---

## 📌 Usage

```powershell
# Mode 1: Generate Challenges
.\entra-id-pre-provision-keys-onespan-fx7.ps1 `
    -Mode generate-challenges `
    -TenantId "your-tenant-guid" `
    -CsvPath ".\input-upns.csv" `
    -OutputPath ".\to-onespan.csv"

# Mode 2: Register Pre-Provisioned Credentials
.\entra-id-pre-provision-keys-onespan-fx7.ps1 `
    -Mode register-credentials `
    -TenantId "your-tenant-guid" `
    -CsvPath ".\tokens.csv" `
    -Force
```

---

## 🧼 Script Parameters

| Parameter      | Description |
|----------------|-------------|
| `-Mode`        | `generate-challenges` or `register-credentials` (**required**) |
| `-TenantId`    | Microsoft Entra ID Tenant GUID (**required**) |
| `-CsvPath`     | Input CSV file path (**required**) |
| `-OutputPath`  | Output CSV path (optional, `generate-challenges` mode only) |
| `-LogPath`     | Optional log file output directory |
| `-VerboseLogging` | Enables detailed debug logs |
| `-DryRun`      | Skips actual Graph updates, useful for testing |
| `-Force`       | Skips confirmation prompts |

---

## 🧪 Test Modes

- When the environment variable `TEST_MODE=1` is set, the script will **not auto-run**. This is required for unit testing.

---

## 📋 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of changes.

---

## 📄 License

MIT License – © [Will LaSala](https://github.com/wlasala) / OneSpan

---

## 🙌 Contributions

Feedback, improvements, and forks welcome. If you find a bug or want to contribute, feel free to open a pull request or issue.
