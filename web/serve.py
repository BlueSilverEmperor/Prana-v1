#!/usr/bin/env python3
"""
Simple local server for Saakshi / Project Vero Web HUD.
Runs on http://localhost:3000
"""

import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 3000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def run():
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"\n=======================================================")
        print(f"  SAAKSHI ZERO-TRUST DEMO HUD RUNNING ON PORT {PORT}")
        print(f"  URL: http://localhost:{PORT}")
        print(f"=======================================================\n")
        print("Press Ctrl+C to stop the server.\n")
        try:
            webbrowser.open(f"http://localhost:{PORT}")
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")

if __name__ == "__main__":
    run()
