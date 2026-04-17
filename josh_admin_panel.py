# ============================================================
#  VULNERABILITY: Publicly Accessible Admin Panel
#  Target: admin.0x10.cloud
#  Author: Joshua Zaakir
# ============================================================

#  This vulnerability occurs when an admin panel is exposed
#  to the public without requiring authentication.
#
#  In this case, the admin panel at admin.0x10.cloud is
#  accessible by anyone and displays sensitive information such as:
#  - System status (CPU, memory, disk usage)
#  - Active users
#  - Database connection details
#  - Database password
#
#  This is a serious security risk because attackers can:
#  - View sensitive system information
#  - Access database credentials
#  - Use this data to attempt further attacks on the system
#
#  Technique:
#  Send a request to the admin panel and check if the page
#  contains the warning message indicating it should not
#  be publicly accessible.

import urllib.request
import urllib.error
import time

print("=" * 50)
print("  Admin Panel Exposure Tester")
print("=" * 50)

# --- Configuration ---
target = "http://admin.0x10.cloud"

print(f"\n  [1] Testing {target} for public admin access...")

try:
    # Respect rate limiting (10 requests/sec)
    time.sleep(0.15)

    # Send request to admin panel
    response = urllib.request.urlopen(target, timeout=5)
    html_code = response.read().decode("utf-8")

    print(f"      [-] HTTP Status Code: {response.status}")

    # --- Check for vulnerability indicators ---
    found = False

    # Warning message clearly indicates misconfiguration
    if "should not be publicly accessible" in html_code:
        print("      [-] Warning message detected on page.")
        found = True

    # Sensitive database info exposure
    if "DB Password" in html_code or "mysql_r00t" in html_code:
        print("      [-] Database credentials exposed on page.")
        found = True

    # --- Final result ---
    if found:
        print("\n  [!] VULNERABILITY FOUND")
        print("      [-] Admin panel is publicly accessible.")
        print("      [-] Sensitive system and database information is exposed.")
    else:
        print("\n  [OK] No admin panel exposure detected.")

except urllib.error.HTTPError as e:
    print(f"\n  [ERROR] HTTP Error: {e.code}")
except urllib.error.URLError as e:
    print(f"\n  [ERROR] URL Error: {e.reason}")
except Exception as e:
    print(f"\n  [ERROR] Unexpected issue: {e}")

print("\n" + "=" * 50)