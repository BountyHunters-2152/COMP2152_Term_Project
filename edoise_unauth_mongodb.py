# ============================================================
#  VULNERABILITY: MongoDB Authentication Disabled
#  Target: mongo.0x10.cloud:27017
#  Author: [EdoiseO]
# ============================================================
#
#  MongoDB is a database service that normally should not be
#  exposed publicly without authentication.
#
#  This vulnerability occurs when:
#  - The MongoDB port is reachable from the internet
#  - The server answers a MongoDB command without credentials
#  - The response reports that authentication is disabled
#
#  This allows attackers to:
#  - Identify the database software and version
#  - Confirm that no username or password is required
#  - Potentially access database metadata or sensitive data
#
#  Technique:
#  Connect to mongo.0x10.cloud on port 27017 using a Python socket,
#  send a safe read-only MongoDB hello request, then analyze the
#  response for the phrase "authentication":"disabled".
#
#  This proof is read-only. It does not write, delete, modify,
#  brute force, or attempt to dump database contents.
# ============================================================

import socket
import struct
import time


# --- Configuration ---
TARGET = "mongo.0x10.cloud"
PORT = 27017
TIMEOUT_SECONDS = 3
MAX_ATTEMPTS = 3


def _cstring(value):
    # MongoDB field names use null-terminated strings.
    return value.encode("utf-8") + b"\x00"


def _bson_int32(name, value):
    # Build a minimal BSON integer field.
    return b"\x10" + _cstring(name) + struct.pack("<i", value)


def _bson_string(name, value):
    # Build a minimal BSON string field.
    raw = value.encode("utf-8") + b"\x00"
    return b"\x02" + _cstring(name) + struct.pack("<i", len(raw)) + raw


def _bson_document(elements):
    # Build a minimal BSON document from encoded fields.
    body = b"".join(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def build_hello_message():
    # Build a MongoDB OP_MSG packet containing a read-only hello command.
    document = _bson_document(
        [
            _bson_int32("hello", 1),
            _bson_string("$db", "admin"),
        ]
    )

    request_id = 1
    response_to = 0
    op_code = 2013
    flag_bits = 0
    section_kind = b"\x00"
    payload = struct.pack("<i", flag_bits) + section_kind + document
    message_length = 16 + len(payload)

    header = struct.pack("<iiii", message_length, request_id, response_to, op_code)
    return header + payload


def extract_response_text(raw_response):
    # Decode the response while preserving readable text.
    return raw_response.decode("utf-8", errors="replace")


print("=" * 50)
print("  MongoDB Authentication Check")
print("=" * 50)

print(f"\n  [1] Testing {TARGET}:{PORT} for disabled MongoDB authentication...")

found = False
last_error = None
response_text = ""

for attempt in range(1, MAX_ATTEMPTS + 1):
    try:
        # Respect the class rate limit and avoid hammering the service.
        time.sleep(0.15)

        # Connect, send the read-only hello command, and read the response.
        with socket.create_connection((TARGET, PORT), timeout=TIMEOUT_SECONDS) as sock:
            sock.settimeout(TIMEOUT_SECONDS)
            sock.sendall(build_hello_message())
            response = sock.recv(4096)

        response_text = extract_response_text(response)

        if response_text:
            print(f"      [-] MongoDB service answered on attempt {attempt}.")
            break

        print(f"      [-] Attempt {attempt}: service connected but returned no data.")

    except socket.timeout as error:
        last_error = error
        print(f"      [-] Attempt {attempt}: connection timed out.")
    except socket.error as error:
        last_error = error
        print(f"      [-] Attempt {attempt}: connection failed ({error}).")

if response_text:
    clean_response = response_text[:500].replace("\x00", "").replace("\n", "\n      ")
    print("\n      [-] Response excerpt:")
    print(f"      {clean_response}")

    # Analyze response for authentication status.
    if '"authentication":"disabled"' in response_text:
        print("      [-] Authentication disabled flag detected.")
        found = True

    if '"version":"' in response_text:
        print("      [-] MongoDB version information exposed.")

    # Final result.
    if found:
        print("\n  [!] VULNERABILITY FOUND")
        print("      [-] MongoDB is reachable without credentials.")
        print("      [-] The response indicates authentication is disabled.")
        print("      [-] Exposed databases can leak metadata or sensitive data.")
    else:
        print("\n  [OK] MongoDB answered, but disabled authentication was not confirmed.")
else:
    print("\n  [ERROR] No readable MongoDB response was received.")
    if last_error:
        print(f"      [-] Last error: {last_error}")
    print("      [-] The service may be rate limiting or closing test connections.")

print("\n" + "=" * 50)
