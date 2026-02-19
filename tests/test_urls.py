#!/usr/bin/env python3

import socket
import json

def test_urls_discovery(host, port):
    """Test to see what URLs are available by checking common endpoints."""
    
    endpoints = [
        "/",
        "/api/",
        "/api/entries/", 
        "/api/tags/",
        "/entries/",
        "/admin/",
        "/api-docs/",
        "/static/",
    ]
    
    print("Testing URL availability...")
    print("=" * 50)
    
    for endpoint in endpoints:
        try:
            request = f"GET {endpoint} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((host, port))
                s.sendall(request.encode())
                
                response = b""
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 4096:  # Limit response size
                        break
                
                if response.startswith(b"HTTP/"):
                    status_line = response.split(b"\r\n")[0]
                    status_code = status_line.split(b" ")[1].decode()
                    print(f"{endpoint:20} -> {status_code}")
                else:
                    print(f"{endpoint:20} -> INVALID RESPONSE")
                    
        except Exception as e:
            print(f"{endpoint:20} -> ERROR: {type(e).__name__}")

if __name__ == "__main__":
    test_urls_discovery("localhost", 8000)