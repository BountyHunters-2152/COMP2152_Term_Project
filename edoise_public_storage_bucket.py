# ============================================================
#  VULNERABILITY: Public Storage Bucket Listing
#  Target: storage.0x10.cloud
#  Author: [EdoiseO]
# ============================================================

# Public storage bucket exposure happens when a cloud storage
# service allows anonymous users to list files without logging in.
#
# This allows attackers to:
# - Discover backup files and database dumps
# - Find credential or environment configuration files
# - Learn internal file names and system structure
# - Target sensitive files for later download attempts
#
# In this case, storage.0x10.cloud returns an S3-style XML bucket
# listing to an unauthenticated HTTP request. The listing includes
# sensitive-looking keys such as:
# - backups/db-2024-03.sql
# - credentials.csv
# - config/production.env
# - logs/access.log
#
# Technique:
# Send a GET request to the storage service, parse the XML response,
# then analyze object keys for sensitive file names and extensions.
# ============================================================

import time
import urllib.request
import xml.etree.ElementTree as ET


print("=" * 50)
print("  Public Storage Bucket Tester")
print("=" * 50)

# --- Configuration ---
target = "http://storage.0x10.cloud/"

# File names and extensions that commonly indicate sensitive data.
sensitive_indicators = [
    "credential",
    "password",
    "secret",
    "backup",
    ".sql",
    ".env",
    ".log",
]

print(f"\n  [1] Checking {target} for public bucket listing...")

try:
    time.sleep(0.15)  # respect server rate limit

    request = urllib.request.Request(
        target,
        headers={"User-Agent": "COMP2152-storage-check"},
    )
    response = urllib.request.urlopen(request, timeout=5)
    xml_body = response.read().decode("utf-8")

    # Parse the S3-style XML response.
    root = ET.fromstring(xml_body)
    namespace = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
    bucket_name = root.findtext("s3:Name", default="Unknown", namespaces=namespace)
    keys = [
        key.text
        for key in root.findall("s3:Contents/s3:Key", namespace)
        if key.text
    ]

    print(f"      [-] HTTP status: {response.status}")
    print(f"      [-] Bucket name: {bucket_name}")
    print(f"      [-] Public objects listed: {len(keys)}")

    found_sensitive_keys = []

    for key in keys:
        print(f"      [-] Object listed: {key}")
        lower_key = key.lower()

        if any(indicator in lower_key for indicator in sensitive_indicators):
            found_sensitive_keys.append(key)

    if found_sensitive_keys:
        print("\n  [!] VULNERABILITY FOUND")
        print("      [-] The storage bucket is publicly listable.")
        print("      [-] Sensitive-looking object names are exposed:")

        for key in found_sensitive_keys:
            print(f"          - {key}")

        print("      [-] Public listings can reveal backups, credentials, configs, and logs.")
    else:
        print("\n  [OK] Bucket listing was readable, but no sensitive names were found.")

except ET.ParseError as error:
    print(f"\n  [ERROR] Response was not valid XML: {error}")
except Exception as error:
    print(f"\n  [ERROR] Request failed: {error}")

print("\n" + "=" * 50)
