import pandas as pd
import requests
import json
import os
import re
from datetime import datetime
from requests.auth import HTTPBasicAuth

BASE_URL = "https://api.aryabhat.ai"
LOGIN_ENDPOINT = f"{BASE_URL}/api/auth/login"

VALID_USERNAME = "valid_mail@gmail.com"
VALID_PASSWORD = "valid_password_123"

DOC_USERNAME = "Doc_user"
DOC_PASSWORD = "Doc_password_123"

# Global storage for variable substitution
stored_values = {}
dep_test_results = {}


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
    """Build headers dynamically from Excel input."""
    if pd.isna(header_field) or not str(header_field).strip():
        return {}

    header_field = str(header_field).strip()

    if header_field.lower() == "auth_headers":
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        if tokens.get("session_token"):
            headers["Session-Token"] = tokens["session_token"]
        return headers

    if header_field.lower() == "refresh_headers":
        return {"Authorization": f"Bearer {tokens['refresh_token']}"}

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
            "Authorization": "Bearer inactive_user_token_789",
            "Session-Token": "inactive_session_987"
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


def substitute_variables(data):
    """
    Recursively replace {{TestID.key}} placeholders using stored values.
    Handles nested dictionaries, lists, and strings.
    """
    if isinstance(data, dict):
        return {k: substitute_variables(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [substitute_variables(item) for item in data]
    elif isinstance(data, str):
        # Find all {{test_id.key}} patterns
        pattern = r'{{\s*([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\s*}}'
        
        def replace_match(match):
            test_id = match.group(1)
            key = match.group(2)
            
            # Check if we have this value stored
            if test_id in stored_values and key in stored_values[test_id]:
                return str(stored_values[test_id][key])
            else:
                print(f"[WARN] Variable not found: {test_id}.{key}")
                return match.group(0)  # Return original if not found
        
        # Replace all occurrences
        return re.sub(pattern, replace_match, data)
    else:
        return data


def load_payload(payload_field):
    """Safely parse JSON payload from Excel cell with variable substitution."""
    if pd.isna(payload_field) or not str(payload_field).strip():
        return {}
    try:
        payload = json.loads(payload_field)
        return substitute_variables(payload)
    except json.JSONDecodeError:
        # If not valid JSON, treat as string and apply substitution
        substituted = substitute_variables(str(payload_field))
        try:
            # Try to parse again after substitution
            return json.loads(substituted)
        except json.JSONDecodeError:
            print(f"[WARN] Invalid payload after substitution: {substituted}")
            return {}
    except Exception as e:
        print(f"[WARN] Error processing payload: {e}")
        return {}


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
            f[1].close()


def parse_expected_status(status_field):
    """Convert Excel Expected_Status field to list of integers."""
    if pd.isna(status_field) or not str(status_field).strip():
        return [200]
    
    status_str = substitute_variables(str(status_field))
    return [int(s.strip()) for s in status_str.split(",")]


def extract_and_store_values(test_id, response_data):
    """
    Extract values from successful responses and store them for future substitution.
    Also handles special extraction patterns.
    """
    if not isinstance(response_data, dict):
        return
    
    # Store the entire response
    stored_values[test_id] = response_data.copy()
    
    # Extract specific values that might be useful
    if "chat_id" in response_data:
        stored_values[test_id]["chat_id"] = response_data["chat_id"]
    if "notebook_id" in response_data:
        stored_values[test_id]["notebook_id"] = response_data["notebook_id"]
    if "user_id" in response_data:
        stored_values[test_id]["user_id"] = response_data["user_id"]
    if "message" in response_data and "created successfully" in str(response_data["message"]):
        # Extract ID from creation messages
        if "_id" in response_data:
            stored_values[test_id]["_id"] = response_data["_id"]
            stored_values[test_id]["id"] = response_data["_id"]


def evaluate_test_result(status_code, expected_status_list, response_data, expected_keys):
    """Evaluate test result based on status code and expected keys."""
    # Check status code
    if status_code in expected_status_list:
        result = "PASS"
        remarks = f"Expected {expected_status_list}, got {status_code}"
    else:
        result = "FAIL"
        remarks = f"Expected {expected_status_list}, got {status_code}"

    # Check expected keys for PASS cases
    if result == "PASS" and expected_keys and expected_keys != [""]:
        clean_keys = [k.strip().strip('"').strip("'") for k in expected_keys]
        missing_keys = []
        
        def check_nested_keys(data, keys):
            """Recursively check for nested keys using dot notation."""
            for key in keys:
                if '.' in key:
                    # Handle nested keys like "data.user.id"
                    parts = key.split('.')
                    current = data
                    try:
                        for part in parts:
                            if isinstance(current, dict) and part in current:
                                current = current[part]
                            else:
                                missing_keys.append(key)
                                break
                    except (KeyError, TypeError):
                        missing_keys.append(key)
                else:
                    # Handle top-level keys
                    if key not in data:
                        missing_keys.append(key)
        
        check_nested_keys(response_data, clean_keys)
        
        if missing_keys:
            result = "FAIL"
            remarks = f"Missing keys: {', '.join(missing_keys)}"

    return result, remarks


def run_tests_from_excel(file_path: str):
    """Main function to run tests from Excel file."""
    global stored_values, dep_test_results
    
    # Reset global storage
    stored_values = {}
    dep_test_results = {}
    
    print("Logging in to fetch tokens...")
    tokens = login_and_get_tokens()

    print("Reading test cases from Excel...")
    df = pd.read_excel(file_path)
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
        
        # Apply variable substitution to endpoint
        endpoint = BASE_URL + substitute_variables(str(endpoint_field))
        
        headers = build_headers(row.get("Headers", ""), tokens)
        params = load_payload(row.get("Params", {}))
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

        depends_on = str(row.get("Depends_On", "")).split(",") if pd.notna(row.get("Depends_On")) else []

        # Dependency check
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
            # Handle different endpoint types
            if any(ep in endpoint for ep in ["/api/docs", "/api/redoc"]):
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
            
            # Parse response
            try:
                resp_json = response.json()
                if "raw" in resp_json and isinstance(resp_json["raw"], str):
                    try:
                        nested = json.loads(resp_json["raw"])
                        if isinstance(nested, dict):
                            resp_json = nested
                    except json.JSONDecodeError:
                        pass
            except Exception:
                resp_json = {"raw": response.text}

            # Evaluate result
            result, remarks = evaluate_test_result(status_code, expected_status_list, resp_json, expected_keys)

            # Store values for dependent tests
            if test_id in dependent_tests:
                dep_test_results[test_id] = result
            
            # Extract and store values for variable substitution
            if result == "PASS" and isinstance(resp_json, dict):
                extract_and_store_values(test_id, resp_json)

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

    # Ensure the folder exists before saving
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
    """Main entry point for running the test suite."""
    results_df = run_tests_from_excel("testdata/test_cases.xlsx")

    # Optional validation: fail test if any FAIL or ERROR found
    failed = results_df[results_df["Result"].isin(["FAIL", "ERROR"])]
    assert failed.empty, f"Some tests failed:\n{failed[['Test_ID','Test_Name','Result']]}"


if __name__ == "__main__":
    test_run_excel_suite()