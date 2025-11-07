import pandas as pd
import requests
import json
import os
import re
from datetime import datetime
from requests.auth import HTTPBasicAuth
from mapper.config_mapper import mapper 

BASE_URL = "https://api.aryabhat.ai"
LOGIN_ENDPOINT = f"{BASE_URL}/api/auth/login"

VALID_USERNAME = ""
VALID_PASSWORD = ""

DOC_USERNAME = ""
DOC_PASSWORD = ""

# Global storage for variable substitution
stored_values = {}
dep_test_results = {}

# Toggle: when True, useful scalar values extracted from responses are merged into mapper
UPDATE_MAPPER_FROM_STORED = True


def apply_mapping(data, mapper_dict):
    """
    Recursively replace string values in dict/list that exactly match keys in mapper_dict.
    - If data is a dict/list, traverse recursively.
    - If data is a string and exactly matches a mapper key, replace it with mapper value.
    Note: mapping only replaces exact matches (not substrings) to avoid accidental replacements.
    """
    if isinstance(data, dict):
        return {k: apply_mapping(v, mapper_dict) for k, v in data.items()}
    if isinstance(data, list):
        return [apply_mapping(i, mapper_dict) for i in data]
    if isinstance(data, str):
        return mapper_dict.get(data, data)
    return data


def update_mapper_from_stored(stored, mapper_dict):
    """
    Merge simple scalar values from stored_values into mapper_dict.
    Keys will be of the form "<TestID>.<key>" (e.g., 'TC01.access_token') so they can be referenced directly.
    Only adds keys that don't already exist in mapper_dict to avoid overwriting explicit config.
    """
    for test_id, data in stored.items():
        if not isinstance(data, dict):
            continue
        for k, v in data.items():
            if isinstance(v, (str, int, float, bool)):
                key = f"{test_id}.{k}"
                if key not in mapper_dict:
                    mapper_dict[key] = str(v)
    return mapper_dict


def substitute_variables(data):
    """
    Recursively replace {{TestID.key.nested}} placeholders using stored_values.
    - This is the DYNAMIC substitution step (runs BEFORE static mapping).
    - If referenced stored key is missing, placeholder remains unchanged.
    """
    if isinstance(data, dict):
        return {k: substitute_variables(v) for k, v in data.items()}
    if isinstance(data, list):
        return [substitute_variables(i) for i in data]
    if isinstance(data, str):
        # pattern matches {{TC01.key.subkey}}
        pattern = r'{{\s*([A-Za-z0-9_]+)\.([A-Za-z0-9_.]+)\s*}}'

        def repl(m):
            test_id = m.group(1)
            key_path = m.group(2)
            if test_id not in stored_values:
                # not found — leave placeholder as-is
                return m.group(0)
            current = stored_values[test_id]
            for key in key_path.split('.'):
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return m.group(0)
            return str(current)

        return re.sub(pattern, repl, data)
    return data


def login_and_get_tokens():
    """Authenticate and return tokens (access, refresh, session)."""
    payload = {
        "grant_type": "password",
        "username": VALID_USERNAME,
        "password": VALID_PASSWORD,
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(LOGIN_ENDPOINT, data=payload, headers=headers)
    response.raise_for_status()
    data = response.json()

    tokens = {
        "access_token": data.get("access_token"),
        "refresh_token": data.get("refresh_token"),
        "session_token": response.cookies.get("session_token") or data.get("session_token"),
    }
    return tokens


def build_headers(header_field, tokens):
    """Build headers dynamically from Excel input, then apply dynamic substitution & static mapping later."""
    if pd.isna(header_field) or not str(header_field).strip():
        return {}

    header_field = str(header_field).strip()

    if header_field.lower() == "auth_headers":
        headers = {"Authorization": f"Bearer {tokens.get('access_token')}"}
        if tokens.get("session_token"):
            headers["Session-Token"] = tokens["session_token"]
        return headers

    if header_field.lower() == "refresh_headers":
        return {"Authorization": f"Bearer {tokens.get('refresh_token')}"}

    if header_field == "invalid_auth_headers":
        return {
            "Authorization": "Bearer invalid_or_expired_token_123",
            "Session-Token": "invalid_session_456"
        }

    if header_field == "expired_auth_headers":
        return {
            "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJKb2huIiwiZXhwIjoxNzYwNTIzNDMyfQ.Z7Sar_CrlHeI2WICE-HZdQqksGUc3LXj6Tp1tHspD7334o63BxnzAGAQTVnI8KaXumLUag_-1JKhEzakcmNBGesSHxXWImd71M1lEFFE1ApXoFEDQ_9Xmkz1Ieea8BARr87ZdelzI8zSSCqQPxkYFTbeltcJQtd_vjZ_-BX2cYxUVBwgcqQQs2dyJrLSYg9zSNXpjUHEYP8BXflK9RzJpIEznLx4zfdWYFChGOc5ois4c9472oEZuU5R2LKJGjZ662qKbA2gnYsLv5D5LWLE_buicc4w5V5B4yPG0MVcXDG-1dMIR4czS-mNZSJXAwvSgMeW4AI7f_9luh12bjZehA",
            "Session-Token": "df9d35b2-6a34-458b-8713-d9b5526ce5fc"
        }

    if header_field == "inactive_auth_headers":
        return {
            "Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJKb2huIiwiZXhwIjoxNzYwNTIzNDMyfQ.Z7Sar_CrlHeI2WICE-HZdQqksGUc3LXj6Tp1tHspD7334o63BxnzAGAQTVnI8KaXumLUag_-1JKhEzakcmNBGesSHxXWImd71M1lEFFE1ApXoFEDQ_9Xmkz1Ieea8BARr87ZdelzI8zSSCqQPxkYFTbeltcJQtd_vjZ_-BX2cYxUVBwgcqQQs2dyJrLSYg9zSNXpjUHEYP8BXflK9RzJpIEznLx4zfdWYFChGOc5ois4c9472oEZuU5R2LKJGjZ662qKbA2gnYsLv5D5LWLE_buicc4w5V5B4yPG0MVcXDG-1dMIR4czS-mNZSJXAwvSgMeW4AI7f_9luh12bjZehA",
            "Session-Token": "df9d35b2-6a34-458b-8713-d9b5526ce5fc"
        }

    # Custom headers in key:value form
    if ":" in header_field:
        key, value = header_field.split(":", 1)
        return {key.strip(): substitute_variables(value.strip())}

    # JSON headers
    try:
        headers_dict = json.loads(header_field)
        return substitute_variables(headers_dict)
    except Exception:
        return {}


def load_payload(payload_field):
    """Safely parse JSON payload from Excel cell, perform dynamic substitution first, then static mapping."""
    if pd.isna(payload_field) or not str(payload_field).strip():
        return {}

    raw = str(payload_field).strip()
    try:
        parsed = json.loads(raw)
    except Exception:
        # try substituting placeholders in raw string and parse again
        substituted_raw = substitute_variables(raw)
        try:
            parsed = json.loads(substituted_raw)
        except Exception:
            print(f"[WARN] Invalid payload JSON for cell (after substitution): {payload_field}")
            return {}

    # Step 1: dynamic substitution ({{TCID.key}}) on parsed structure
    parsed = substitute_variables(parsed)

    # Step 2: static mapping
    parsed = apply_mapping(parsed, mapper)

    return parsed


def load_params(params_field):
    """Safely parse JSON params from Excel, dynamic substitute then static map."""
    if pd.isna(params_field) or not str(params_field).strip():
        return {}

    raw = str(params_field).strip()
    try:
        parsed = json.loads(raw)
    except Exception:
        substituted_raw = substitute_variables(raw)
        try:
            parsed = json.loads(substituted_raw)
        except Exception:
            print(f"[WARN] Invalid params JSON for cell (after substitution): {params_field}")
            return {}

    parsed = substitute_variables(parsed)
    parsed = apply_mapping(parsed, mapper)
    return parsed


def load_files(file_field):
    """Handle optional file uploads with variable substitution in file paths."""
    if pd.isna(file_field) or not str(file_field).strip():
        return None

    file_path = substitute_variables(str(file_field).strip())

    if not os.path.exists(file_path):
        print(f"[WARN] File not found: {file_path}")
        return None

    mime = "image/jpeg" if file_path.lower().endswith((".jpg", ".jpeg")) else "application/octet-stream"
    return {"profile_picture": (os.path.basename(file_path), open(file_path, "rb"), mime)}


def close_files(files):
    """Close opened file handles."""
    if files:
        for f in files.values():
            # f is tuple (filename, fileobj, mime)
            try:
                if hasattr(f[1], "close"):
                    f[1].close()
            except Exception:
                pass


def parse_expected_status(status_field):
    """Convert Excel Expected_Status field to list of integers."""
    if pd.isna(status_field) or not str(status_field).strip():
        return [200]

    status_str = substitute_variables(str(status_field))
    return [int(s.strip()) for s in status_str.split(",")]


def extract_and_store_values(test_id, response_data):
    """
    Extract values from successful responses and store them for future substitution.
    Also stores some common fields for convenience.
    """
    if not isinstance(response_data, dict):
        return

    stored_values[test_id] = response_data.copy()

    for key in ("chat_id", "notebook_id", "user_id", "id", "_id", "token", "access_token", "refresh_token"):
        if key in response_data:
            stored_values[test_id][key] = response_data[key]

    # message based extraction
    if "message" in response_data and ("created" in str(response_data["message"]).lower()) and "_id" in response_data:
        stored_values[test_id]["_id"] = response_data["_id"]
        stored_values[test_id]["id"] = response_data["_id"]


def evaluate_test_result(status_code, expected_status_list, response_data, expected_keys):
    """Evaluate test result based on status code and expected keys."""
    if status_code in expected_status_list:
        result = "PASS"
        remarks = f"Expected {expected_status_list}, got {status_code}"
    else:
        result = "FAIL"
        remarks = f"Expected {expected_status_list}, got {status_code}"

    if result == "PASS" and expected_keys and expected_keys != [""]:
        clean_keys = [k.strip().strip('"').strip("'") for k in expected_keys]
        missing_keys = []

        def check_nested_keys(data, keys):
            for key in keys:
                if '.' in key:
                    parts = key.split('.')
                    current = data
                    found = True
                    for p in parts:
                        if isinstance(current, dict) and p in current:
                            current = current[p]
                        else:
                            found = False
                            break
                    if not found:
                        missing_keys.append(key)
                else:
                    if key not in data:
                        missing_keys.append(key)

        check_nested_keys(response_data, clean_keys)
        if missing_keys:
            result = "FAIL"
            remarks = f"Missing keys: {', '.join(missing_keys)}"

    return result, remarks


def run_tests_from_excel(file_path: str):
    """Main function to run tests from Excel file."""
    global stored_values, dep_test_results, mapper

    # Reset global storage
    stored_values = {}
    dep_test_results = {}

    print("Logging in to fetch tokens...")
    tokens = login_and_get_tokens()

    print("Reading test cases from Excel...")
    df = pd.read_excel(file_path)

    # Validate required columns
    required_columns = ["Test_ID", "Method", "Endpoint", "Run_Flag"]
    missing_cols = [col for col in required_columns if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing required columns in Excel: {missing_cols}")

    results = []
    os.makedirs("reports", exist_ok=True)

    # Identify dependent tests
    dependent_tests = set()
    for _, row in df.iterrows():
        if pd.notna(row.get("Depends_On")) and str(row.get("Depends_On")).strip():
            for dep in str(row.get("Depends_On")).split(","):
                dependent_tests.add(dep.strip())

    for _, row in df.iterrows():
        if str(row.get("Run_Flag", "")).lower() != "yes":
            continue

        test_id = str(row.get("Test_ID", "")).strip()
        api_group = row.get("API_Group", "")
        test_name = row.get("Test_Name", "")
        method = str(row.get("Method", "GET")).upper()
        endpoint_field = row.get("Endpoint", "")

        endpoint = BASE_URL + substitute_variables(str(endpoint_field))
        endpoint = apply_mapping(endpoint, mapper) if isinstance(endpoint, str) else endpoint

        headers = build_headers(row.get("Headers", ""), tokens)

        headers = substitute_variables(headers)
        headers = apply_mapping(headers, mapper)

        # Load params and payload (dynamic substitution then static mapping inside functions)
        params = load_params(row.get("Params", {}))
        payload = load_payload(row.get("Payload", {}))
        files = load_files(row.get("Files", None))
        expected_status_list = parse_expected_status(row.get("Expected_Status", 200))

        # Parse expected keys
        expected_keys = []
        if pd.notna(row.get("Expected_Keys")):
            expected_keys_str = substitute_variables(str(row.get("Expected_Keys")))
            try:
                expected_keys = json.loads(expected_keys_str)
            except Exception:
                expected_keys = [k.strip().strip('"').strip("'") for k in expected_keys_str.split(",")]

        # Dependency check
        depends_on = str(row.get("Depends_On", "")).split(",") if pd.notna(row.get("Depends_On")) else []
        skip_test = False
        for dep in depends_on:
            dep = dep.strip()
            if dep and dep_test_results.get(dep) != "PASS":
                print(f"⏭ Skipping {test_name} because dependency {dep} failed or was skipped.")
                results.append({
                    "Test_ID": test_id,
                    "API_Group": api_group,
                    "Test_Name": test_name,
                    "Method": method,
                    "Endpoint": endpoint,
                    "Status_Code": "N/A",
                    "Result": "SKIPPED",
                    "Remarks": f"Dependency {dep} failed or not executed.",
                    "Response": ""
                })
                skip_test = True
                break

        if skip_test:
            if test_id in dependent_tests:
                dep_test_results[test_id] = "SKIPPED"
            continue

        print(f"\n>>Running: {test_name} → {method} {endpoint}")
        try:
            # Handle different endpoint types as before
            if any(ep in endpoint for ep in ["/api/docs", "/api/redoc"]):
                if headers in ["invalid_auth"]:
                    response = requests.request(
                        method=method,
                        url=endpoint,
                        headers={"accept": "text/html"},
                        timeout=30,
                    )
                else:
                    response = requests.request(
                        method=method,
                        url=endpoint,
                        auth=HTTPBasicAuth(DOC_USERNAME, DOC_PASSWORD),
                        headers={"accept": "text/html"},
                        timeout=30,
                    )

            elif "/register" in endpoint:
                response = requests.request(
                    method=method,
                    url=endpoint,
                    headers=headers,
                    data=payload if payload else None,
                    files=files if files else None,
                    timeout=30,
                )

            elif any(ep in endpoint for ep in ["/signup", "/login", "/resend", "/forgot-password", "/update-password"]):
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                response = requests.request(
                    method=method,
                    url=endpoint,
                    headers=headers,
                    data=payload if payload else None,
                    timeout=30,
                )

            elif any(ep in endpoint for ep in ["/api/auth/google", "/api/auth/microsoft"]):
                response = requests.request(
                    method=method,
                    url=endpoint,
                    headers=headers,
                    params=params if params else None,
                    json=payload if payload else None,
                    timeout=30,
                    allow_redirects=False  
                )

            else:
                response = requests.request(
                    method=method,
                    url=endpoint,
                    headers=headers,
                    params=params if params else None,
                    json=payload if payload else None,
                    files=files if files else None,
                    timeout=30,
                )

            status_code = response.status_code

            # Parse response robustly
            try:
                resp_json = response.json()
                # sometimes server returns {"raw": "<json-string>"}
                if isinstance(resp_json, dict) and "raw" in resp_json and isinstance(resp_json["raw"], str):
                    try:
                        nested = json.loads(resp_json["raw"])
                        if isinstance(nested, dict):
                            resp_json = nested
                    except Exception:
                        pass
            except Exception:
                resp_json = {"raw": response.text}

            # Evaluate result
            result, remarks = evaluate_test_result(status_code, expected_status_list, resp_json, expected_keys)

            # Track dependency result
            if test_id in dependent_tests:
                dep_test_results[test_id] = result

            # On PASS, extract and store
            if result == "PASS" and isinstance(resp_json, dict):
                extract_and_store_values(test_id, resp_json)
                if UPDATE_MAPPER_FROM_STORED:
                    # Merge newly stored values into mapper (keys like "TC01.token")
                    update_mapper_from_stored({test_id: stored_values.get(test_id, {})}, mapper)

            results.append({
                "Test_ID": test_id,
                "API_Group": api_group,
                "Test_Name": test_name,
                "Method": method,
                "Endpoint": endpoint,
                "Status_Code": status_code,
                "Result": result,
                "Remarks": remarks,
                "Response": json.dumps(resp_json, indent=2)
            })

        # Exception handling (kept original behaviour)
        except requests.exceptions.Timeout:
            if test_id in dependent_tests:
                dep_test_results[test_id] = "ERROR"

            results.append({
                "Test_ID": test_id,
                "API_Group": api_group,
                "Test_Name": test_name,
                "Method": method,
                "Endpoint": endpoint,
                "Status_Code": "N/A",
                "Result": "ERROR",
                "Remarks": "Request timeout (30s exceeded)",
                "Response": ""
            })

        except requests.exceptions.ConnectionError as e:
            if test_id in dependent_tests:
                dep_test_results[test_id] = "ERROR"

            results.append({
                "Test_ID": test_id,
                "API_Group": api_group,
                "Test_Name": test_name,
                "Method": method,
                "Endpoint": endpoint,
                "Status_Code": "N/A",
                "Result": "ERROR",
                "Remarks": f"Connection error - API may be down: {str(e)}",
                "Response": ""
            })

        except requests.exceptions.RequestException as e:
            if test_id in dependent_tests:
                dep_test_results[test_id] = "ERROR"

            results.append({
                "Test_ID": test_id,
                "API_Group": api_group,
                "Test_Name": test_name,
                "Method": method,
                "Endpoint": endpoint,
                "Status_Code": "N/A",
                "Result": "ERROR",
                "Remarks": f"Request error: {str(e)}",
                "Response": ""
            })

        except Exception as e:
            if test_id in dependent_tests:
                dep_test_results[test_id] = "ERROR"

            results.append({
                "Test_ID": test_id,
                "API_Group": api_group,
                "Test_Name": test_name,
                "Method": method,
                "Endpoint": endpoint,
                "Status_Code": "N/A",
                "Result": "ERROR",
                "Remarks": str(e),
                "Response": ""
            })

        finally:
            close_files(files)

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_folder = "reports"
    os.makedirs(output_folder, exist_ok=True)
    output_file = os.path.join(output_folder, f"test_results_{timestamp}.xlsx")

    results_df = pd.DataFrame(results)
    results_df.to_excel(output_file, index=False)

    # Print summary
    total_tests = len(results_df)
    passed_tests = len(results_df[results_df["Result"] == "PASS"])
    failed_tests = len(results_df[results_df["Result"] == "FAIL"])
    skipped_tests = len(results_df[results_df["Result"] == "SKIPPED"])
    error_tests = len(results_df[results_df["Result"] == "ERROR"])

    print(f"\nTEST SUMMARY:")
    print(f"PASSED: {passed_tests}/{total_tests}")
    print(f"FAILED: {failed_tests}/{total_tests}")
    print(f"SKIPPED: {skipped_tests}/{total_tests}")
    print(f"ERRORS: {error_tests}/{total_tests}")
    print(f"Results saved to: {output_file}")

    return results_df


def test_run_excel_suite():
    """Main entry point for running the test suite in CI (raises on failures)."""
    results_df = run_tests_from_excel("testdata/test_cases.xlsx")
    failed = results_df[results_df["Result"].isin(["FAIL", "ERROR"])]
    assert failed.empty, f"Some tests failed:\n{failed[['Test_ID','Test_Name','Result']]}"


if __name__ == "__main__":
    run_tests_from_excel("testdata/test_cases.xlsx")