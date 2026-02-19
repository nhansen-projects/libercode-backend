#!/usr/bin/env python3

import socket
import time

def test_connection(host, port, timeout=5):
    """Test if a TCP connection can be established to the given host and port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            print(f"✅ SUCCESS: Connection established to {host}:{port}")
            return True
    except socket.timeout:
        print(f"❌ TIMEOUT: No response from {host}:{port} within {timeout} seconds")
    except ConnectionRefusedError:
        print(f"❌ REFUSED: Connection refused to {host}:{port}")
    except Exception as e:
        print(f"❌ ERROR: {type(e).__name__}: {e}")
    return False

def test_http_response(host, port):
    """Test if we can get an HTTP response from the server."""
    try:
        # Create a raw HTTP request
        request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((host, port))
            s.sendall(request)
            
            # Read response
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
                # Stop if we have the headers (first 4096 bytes should be enough)
                if len(response) > 4096:
                    break
            
            # Check if we got a valid HTTP response
            if response.startswith(b"HTTP/"):
                # Extract status code
                status_line = response.split(b"\r\n")[0]
                status_code = status_line.split(b" ")[1].decode()
                print(f"✅ HTTP RESPONSE: Status {status_code}")
                
                # Show first few lines of response
                lines = response.split(b"\r\n")[:5]
                print("Response preview:")
                for line in lines:
                    print(f"  {line.decode().strip()}")
                return True
            else:
                print(f"❌ INVALID RESPONSE: {response[:100]}")
                return False
                
    except Exception as e:
        print(f"❌ HTTP TEST ERROR: {type(e).__name__}: {e}")
        return False

if __name__ == "__main__":
    print("Testing connection to Django server...")
    print("=" * 50)
    
    # Test basic TCP connection
    if test_connection("localhost", 8000):
        print("\nTesting HTTP response...")
        test_http_response("localhost", 8000)
    else:
        print("\nCannot proceed with HTTP test - no connection established")
    
    print("\n" + "=" * 50)
    print("Test completed.")