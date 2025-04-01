# Entra ID FIDO2 Pre-Provisioning Script

This PowerShell script enables automated **FIDO2 credential management** for Microsoft Entra ID (Azure AD) users via the Microsoft Graph API. It supports both:

- ✅ Generating **FIDO2 credential challenges** for OneSpan pre-provisioning
- ✅ Registering **pre-provisioned FIDO2 keys** into Microsoft Entra ID

---

## 📂 Project Structure

```
.
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
- Uses Microsoft Graph (Beta) API
- Fully compatible with **PowerShell 5.1 and 7+**
- Modular functions with high testability
- Built-in logging, dry-run support, and force override
- ⚡ 99% unit test coverage (100% functionally verified)

---

## 🛠️ Requirements

- PowerShell 5.1 or 7+
- [`Microsoft.Graph.Beta`](https://www.powershellgallery.com/packages/Microsoft.Graph.Beta)
- Pester (for testing)

---

## 🧪 Running Unit Tests

Run all unit tests using Pester:

```powershell
Invoke-Pester -Path ./tests
```

💡 **Code coverage** is tracked in `./coverage/coverage.xml`. The remaining 1% of uncovered code is verified via testing but not reported due to [Pester's current coverage limitations](https://github.com/pester/Pester/issues/).

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

## 📄 License

MIT License – © [Will LaSala](https://github.com/wlasala) / OneSpan

---

## 🙌 Contributions

Feedback, improvements, and forks welcome. If you find a bug or want to contribute, feel free to open a pull request or issue.
