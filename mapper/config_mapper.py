mapper = {

    # --- User Accounts & Credentials ---
    "valid_mail": "",   # Should be unregisterd mail
    "valid_mail_pass": "", # Password for unregisterd mail
    "login_mail": "",   # Mail for login tests
    "login_pass": "",           # Password for login tests
    "test_mail": "test_mail@gmail.com",     # Used to invite users
    "nonexistent_mail": "nonexistent@diagonal.ai",
    "invalid_email": "invalid_email@",      # Invalid email format
    "support_mail": "support@diagonal.ai",  # Support email address
    "inactivate_mail": "",   # Mail for unlicensed/inactive account tests
    "username_u": "user",         # To Activate/ Revoke user's license

    # --- OTP / Token / Codes ---
    "valid_otp": "999999",                  # Acutal otp must be given during test since dynamic isnt possibe 
    "invalid_otp": "123456",                # Invalid OTP for negative tests
    "valid_google_code": "<valid_google_code>",
    "valid_microsoft_code": "<valid_microsoft_code>",
    "invalid_code": "invalid_callback_code",     # Invalid code for negative tests

    # --- User IDs / Reference IDs ---
    "valid_userId": "", # Logged in User's user ID (SUPERADMIN)
    "invalid_userId": "invalid_user_123",       
    "nonexistent_userId": "68cbd755a713b399daf534x2",

    # --- Tag & Category ---
    "valid_tag_name": "medical",                # Valid tag name the doesnt exist yet - to create, to fetch, to delete, to rename
    "invalid_tag_name": "NonExistentTag",       
    "invalid_tag_id": "9999999999999",
    "rename_tag": "Works",                      # New name for renaming tag 

    # --- Chat / Notebook ---
    "valid_chat_id": "icnye4gx35",              # Existing chat ID for stop-stream api, React, Show History, Pin 
    "invalid_chat_id": "invalid_chat_999",
    "nonexistent_chat_id": "non-existent-chat-id-999",
    "valid_temperature": 0.5,                   # Valid temperature 
    "valid_user_input": "what is a machine?",   # Valid user input for chat tests
    "valid_dept_tag": "personal",               # Valid department tag for Chat
    "valid_message_id": "",                     # Valid message ID for pin/unpin message tests


    # --- Providers / Models ---
    "valid_provider_id": "68c95a3b15c02201dda52ea8",
    "invalid_provider_id": "invalid_provider_999",
    "valid_model_id": "lwav",
    "invalid_model_id": "invalid_model_999",
    "provider_name": "Ollama",
    "valid_apikey": "dummy_api_key",
    "valid_proxy": "https://dummy.proxy",
    

    # --- Database Config ---
    "db_server": "localhost",
    "db_port": "5432",
    "db_name": "test_db",
    "db_username": "admin",
    "db_password": "admin123",
    "db_schema": "public",
    "db_id": "db_01",
    "db_provider_id": "provider_01",

    # --- SMTP / Email Config ---
    "smtp_server": "smtp.office365.com",
    "smtp_port": 587,
    "support_mail": "support@diagonal.ai",
    "smtp_password": "valid_smtp_password",
    "smtp_security": "StartTLS",

    # --- License Keys ---
    "valid_signed_license_key": "actual_valid_signed_license_key",  # Must be activated
    "revoked_license_key": "valid_signed_license_to_be_revoked",
    "invalid_license_key": "INVALID-KEY-XYZ",

    # --- Buckets / Files (for batch processing) ---
    "valid_bucket": "uploads",                  # S3 storage bucket name
    "invalid_bucket": "invalid_bucket_999",     # Invalid bucket name
    # "file1": "file1.txt",                       # Object keys / file names in the bucket
    # "file2": "file2.txt",                       # Another file name
    "bucket_prefix": "test_files/",             # Prefix/folder in the bucket
    "valid_object_keys": ["file1.txt", "file2.txt"],

    # --- Pagination Defaults ---
    "default_page": 1,
    "default_size": 10,
    "large_page_size": 500,

    # --- Misc / Default Values ---
    "default_country": "India",
    "default_city": "CityName",
    "default_state": "StateName",
    "default_gender": "M",
    "default_dob": "2000-01-01",
    "existing_username": "John",       # Username that already exists in the system
    "new_username": "user",             # New username to registertests
    "unverified_mail": "",                  # Otp verification pending mail


    # --- Cloud Storage (Google Drive / OneDrive) ---
    "valid_folder_id": "valid_folder_123",       # Valid folder ID for Google Drive
    "invalid_folder_id": "invalid_id_999",
    "valid_item_ids": ["file1", "file2"],
    "google_valid_item_ids": ["file1", "file2"],
    "onedrive_valid_item_ids": ["file1", "file2"],
    "invalid_item_ids": ["invalid_file_123"],
    "valid_email": "valid_mail@gmail.com",
    "o_email": "Valid_oneDrive_mail",           # Valid OneDrive email
    "valid_folderId": "valid_folder_123",       # Valid OneDrive folder ID for files


    "llm_endpoint_url": "http://db_server:11434/api/generate",
    "llm_model": "llama3.1:latest",
    "llm_provider_name": "TestProvider",
    "llm_model_name": "TestModel",
    "llm_created_at": "2025-10-10T10:00:00Z",


    "delete_user": "user",            # Pass the username of the user to be deleted
    "user_role": "Admin",                       # Role to assign to the new user

}
