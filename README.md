# ARYABHAT TEST AUTOMATE

**ARYABHAT Test Automate** is a Python-based, data-driven API testing framework that reads test cases from Excel files, executes them dynamically, and generates detailed test reports.  
It supports authentication, dependent tests, file uploads, and variable substitution to streamline automated API validation.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Usage](#usage)
- [Test Case Excel Format](#test-case-excel-format)
- [Reports](#reports)
- [Extending Tests](#extending-tests)
- [Known Limitations](#known-limitations)
- [Example](#example)
- [Troubleshooting](#troubleshooting)

---

## Features

- Executes test cases defined in Excel (`.xlsx`)
- Supports **GET**, **POST**, **PUT**, and **DELETE** HTTP methods
- Built-in **authentication** support for:
  - Valid access tokens
  - Invalid / expired / inactive tokens (negative tests)
- Handles **dependent tests** — automatically skips if prerequisites fail
- Supports **variable substitution** in endpoints, payloads, headers, and files (`{{TestID.key}}`)
- Optional **file upload** handling
- Validates **HTTP status codes** and **JSON response keys**
- Generates timestamped **Excel reports**
- Displays concise **console summaries**

---

## Prerequisites

- **Python** 3.9 or above  
- Install dependencies:

```bash
pip install pandas requests openpyxl
```

* Excel file with test cases (see format below)

---

## ⚙️ Setup

1. **Clone or download** this repository.

2. Place your test case file in:

   ```
   testdata/test_cases.xlsx
   ```

3. Update credentials in the main script (`run_excel_tests.py`):

   ```python
   VALID_USERNAME = "valid_mail@gmail.com"
   VALID_PASSWORD = "valid_password_123"

   DOC_USERNAME = "Doc_user"
   DOC_PASSWORD = "Doc_password_123"
   ```

4. Set the API base URL:

   ```python
   BASE_URL = "https://api.aryabhat.ai"
   ```

---

## Usage

Run directly using Python:

```bash
python run_excel_tests.py
```

Or run with **pytest**:

```bash
pytest run_excel_tests.py -s
```

The script will:

1. Authenticate and retrieve valid tokens  
2. Read test cases from Excel  
3. Execute API requests with dynamic headers, payloads, and file uploads  
4. Validate responses based on status codes and expected JSON keys  
5. Manage dependent tests automatically  
6. Generate detailed Excel reports inside the `reports/` directory

---

## Test Case Excel Format

| Column Name         | Description                                                        |
| ------------------- | ------------------------------------------------------------------ |
| **Test_ID**         | Unique test case identifier                                        |
| **API_Group**       | Module or API group name                                           |
| **Test_Name**       | Short description of the test case                                 |
| **Method**          | HTTP method (`GET`, `POST`, etc.)                                  |
| **Endpoint**        | API endpoint path (`{{TestID.key}}` supported)                     |
| **Headers**         | Header type or JSON (e.g., `auth_headers`, `invalid_auth_headers`) |
| **Params**          | Query parameters in JSON format (optional)                         |
| **Payload**         | Request body in JSON format (supports substitution)                |
| **Files**           | File path for upload (optional)                                    |
| **Expected_Status** | Expected HTTP codes (comma-separated, e.g. `200,201`)              |
| **Expected_Keys**   | Keys expected in response JSON                                     |
| **Run_Flag**        | `Yes` / `No` to control execution                                  |
| **Depends_On**      | Comma-separated Test_IDs that must pass first (optional)           |

---

## Reports

* Reports are automatically saved in:

  ```
  reports/test_results_YYYYMMDD_HHMMSS.xlsx
  ```

| Column Name     | Description                           |
| --------------- | ------------------------------------- |
| **Test_ID**     | Test case ID                          |
| **API_Group**   | Module/API group                      |
| **Test_Name**   | Test description                      |
| **Method**      | HTTP method used                      |
| **Endpoint**    | Full API endpoint tested              |
| **Status_Code** | Returned HTTP status code             |
| **Result**      | `PASS`, `FAIL`, `SKIPPED`, or `ERROR` |
| **Remarks**     | Notes or validation comments          |
| **Response**    | Raw JSON response (formatted)         |

---

## Extending Tests

1. Add new rows to the Excel file following the defined column structure.  
2. Use `{{TestID.key}}` placeholders to reuse values from previous test responses.  
3. Define dependencies using the **Depends_On** column.  
4. To support new authentication or headers, update the `build_headers()` function.

---

## Known Limitations

* Only `.xlsx` format is supported.  
* JSON key validation supports **dot notation** for nested keys.  
* Only **one file upload** is supported per request (`profile_picture`).  
* Currently supports only **JSON** and **form-data** payloads.

---

## Example

**Sample Excel Test Case:**

| Test_ID | API_Group | Test_Name                    | Method | Endpoint              | Headers              | Payload                   | Expected_Status | Run_Flag | Expected_Keys        |
| ------- | --------- | ---------------------------- | ------ | --------------------- | -------------------- | ------------------------- | --------------- | -------- | -------------------- |
| TC01A01 | Tags      | Create tag successfully      | POST   | `/api/Tags/CreateTag` | auth_headers         | `{"tag_name": "new-tag"}` | 201             | Yes      | `["_id","tag_name"]` |
| TC03A02 | Tags      | Create tag with invalid auth | POST   | `/api/Tags/CreateTag` | invalid_auth_headers | `{"tag_name":"fail-tag"}` | 401,403         | Yes      | `[]`                 |

---

## Troubleshooting

| Issue                                | Possible Cause                         | Solution                                      |
| ------------------------------------ | -------------------------------------- | --------------------------------------------- |
| Excel file not found                  | `testdata/test_cases.xlsx` missing    | Add the Excel file at the correct path       |
| Invalid authentication                | Wrong username/password                | Check `VALID_USERNAME` / `VALID_PASSWORD`   |
| Malformed JSON                        | Invalid syntax in Payload/Params       | Validate JSON format                          |
| Dependent test skipped                | Pre-requisite test failed              | Verify prior test results                     |
| Report not generated                  | `reports/` folder missing or no write permission | Create `reports/` folder with write access |

---

## Folder Structure

```
├── testdata/
│   └── test_cases.xlsx
├── reports/
│   └── test_results_YYYYMMDD_HHMMSS.xlsx
├── run_excel_tests.py
├── requirements.txt
└── README.md
```

---

## Summary

This framework enables **consistent, reusable, and scalable** API testing using a simple Excel-driven workflow — perfect for QA engineers, developers, and teams aiming to automate endpoint validation efficiently.
