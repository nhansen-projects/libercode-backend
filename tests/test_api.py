#!/usr/bin/env python3

import socket
import json

def test_api_endpoint(host, port, endpoint="/api/entries/", method="GET", data=None):
    """Test an API endpoint with a raw HTTP request."""
    try:
        if data is None:
            data = {}
            
        # Create HTTP request
        if method == "GET":
            request = f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        elif method == "POST":
            json_data = json.dumps(data)
            request = f"POST {endpoint} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len(json_data)}\r\nConnection: close\r\n\r\n{json_data}"
        else:
            print(f"❌ UNSUPPORTED METHOD: {method}")
            return False
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((host, port))
            s.sendall(request.encode())
            
            # Read response
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Stop if we have enough data
                if len(response) > 16384:  # 16KB should be enough for most responses
                    break
            
            # Parse response
            if response.startswith(b"HTTP/"):
                # Extract status code
                status_line = response.split(b"\r\n")[0]
                status_code = status_line.split(b" ")[1].decode()
                
                # Extract headers and body
                parts = response.split(b"\r\n\r\n", 1)
                headers = parts[0].decode()
                body = parts[1].decode() if len(parts) > 1 else ""
                
                print(f"✅ API RESPONSE: {method} {endpoint}")
                print(f"   Status: {status_code}")
                
                # Show content type
                for header in headers.split("\r\n"):
                    if header.startswith("Content-Type:"):
                        print(f"   Content-Type: {header.split(': ', 1)[1]}")
                        break
                
                # Show body preview if JSON
                if body and "application/json" in headers:
                    try:
                        json_data = json.loads(body)
                        print(f"   Body preview: {json.dumps(json_data, indent=2)[:500]}")
                    except:
                        print(f"   Body: {body[:200]}")
                elif body:
                    print(f"   Body: {body[:200]}")
                
                return True
            else:
                print(f"❌ INVALID RESPONSE: {response[:100]}")
                return False
                
    except Exception as e:
        print(f"❌ API TEST ERROR: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    print("Testing Django API endpoints...")
    print("=" * 50)
    
    # Test GET endpoints
    endpoints = [
        "/api/entries/",
        "/api/tags/",
        "/entries/",
        "/",
    ]
    
    for endpoint in endpoints:
        print(f"\nTesting {endpoint}:")
        test_api_endpoint("localhost", 8000, endpoint)
    
    print("\n" + "=" * 50)
    print("API test completed.")