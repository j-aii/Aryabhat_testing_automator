# ARYABHAT TEST AUTOMATE

This Python script provides a **data-driven API testing framework** that executes test cases defined in an Excel file and generates detailed test reports. It supports variable substitution, file uploads, authentication headers, dependent tests, and response validation.

---

## Table of Contents

* [Features](#features)
* [Prerequisites](#prerequisites)
* [Setup](#setup)
* [Usage](#usage)
* [Test Case Excel Format](#test-case-excel-format)
* [Reports](#reports)
* [Extending Tests](#extending-tests)
* [Known Limitations](#known-limitations)

---

## Features

* Read test cases from an Excel file (`.xlsx`)
* Supports **GET**, **POST**, **PUT**, **DELETE** HTTP methods
* Supports **authentication**:

  * Valid access tokens
  * Invalid/expired/inactive tokens for negative tests
* Handles **dependent tests** (skips tests if dependencies fail)
* Supports **variable substitution** in endpoints, headers, payloads, and file paths (`{{TestID.key}}`)
* Optional **file upload** support
* Validates **status codes** and **expected JSON keys**
* Generates detailed **Excel test reports**
* Logs summary in console

---

## Prerequisites

* Python 3.9+
* Required Python packages:

```bash
pip install pandas requests openpyxl
```

* Excel file containing test cases

---

## Setup

1. Clone this repository or download the script.
2. Ensure your Excel test cases are available in `testdata/test_cases.xlsx`.
3. Update the following credentials in the script:

```python
VALID_USERNAME = "valid_mail@gmail.com"
VALID_PASSWORD = "valid_password_123"

DOC_USERNAME = "Doc_user"
DOC_PASSWORD = "Doc_password_123"
```

4. Update `BASE_URL` to point to your API server.

---

## Usage

Run the test suite directly:

```bash
python run_tests.py
```

Or as a pytest entry point:

```bash
pytest run_tests.py -v
```

The script will:

1. Authenticate and retrieve access tokens
2. Read test cases from Excel
3. Execute API requests with dynamic headers, payloads, and file uploads
4. Evaluate responses for status codes and expected keys
5. Handle dependent tests
6. Generate a detailed Excel report in the `reports/` folder

---

## Test Case Excel Format

The Excel file should have the following columns:

| Column Name       | Description                                                        |
| ----------------- | ------------------------------------------------------------------ |
| `Test_ID`         | Unique identifier for the test case                                |
| `API_Group`       | Module or API group name                                           |
| `Test_Name`       | Brief description of the test case                                 |
| `Method`          | HTTP method (`GET`, `POST`, etc.)                                  |
| `Endpoint`        | API endpoint path (supports `{{TestID.key}}`)                      |
| `Headers`         | Header type or JSON (e.g., `auth_headers`, `invalid_auth_headers`) |
| `Params`          | Query parameters as JSON (optional)                                |
| `Payload`         | Request body as JSON (optional, supports variable substitution)    |
| `Files`           | File paths for upload (optional)                                   |
| `Expected_Status` | Comma-separated expected HTTP status codes (e.g., `200,201`)       |
| `Expected_Keys`   | JSON keys expected in the response                                 |
| `Run_Flag`        | `Yes` or `No` to execute test                                      |
| `Depends_On`      | Comma-separated Test_IDs that this test depends on (optional)      |

---

## Reports

* Reports are saved in the `reports/` folder with a timestamp:
  `reports/test_results_YYYYMMDD_HHMMSS.xlsx`
* Columns in the report:

| Column Name   | Description                           |
| ------------- | ------------------------------------- |
| `Test_ID`     | Test case ID                          |
| `API_Group`   | Module/API group                      |
| `Test_Name`   | Test case description                 |
| `Method`      | HTTP method                           |
| `Endpoint`    | Full API endpoint                     |
| `Status_Code` | Returned HTTP status code             |
| `Result`      | `PASS` / `FAIL` / `SKIPPED` / `ERROR` |
| `Remarks`     | Notes on test evaluation              |
| `Response`    | Raw response (formatted JSON)         |

---

## Extending Tests

1. Add new test cases to the Excel file following the column structure.
2. Use `{{TestID.key}}` to reuse values from previous tests.
3. Define dependencies using the `Depends_On` column.
4. Add new authentication or custom headers in the `build_headers` function if needed.

---

## Known Limitations

* Only `.xlsx` Excel files are supported.
* Nested JSON validation supports dot notation for keys.
* File uploads are limited to one file per request (`profile_picture`).
* Currently only supports JSON and form-encoded payloads.

---

## Example

```python
# Example test case in Excel
Test_ID       API_Group   Test_Name                     Method  Endpoint              Headers         Payload                                      Expected_Status   Run_Flag  Expected_Keys
TC01A01       Tags        Create tag successfully       POST    /api/Tags/CreateTag    auth_headers    {"tag_name": "new-tag"}                       201             Yes       ["_id","tag_name"]
TC03A02       Tags        Create tag with invalid auth POST    /api/Tags/CreateTag    invalid_auth_headers {"tag_name":"fail-tag"}                     401,403         Yes       []
```


