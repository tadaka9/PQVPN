#!/usr/bin/env python3
"""
Simple HTTP server that returns the client's IP address
"""

import http.server
import socketserver

PORT = 8888


class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/ip":
            # Return client IP
            client_ip = self.client_address[0]
            response = f"Your IP: {client_ip}\n"
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.send_header("Content-length", len(response))
            self.end_headers()
            self.wfile.write(response.encode())
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            response = f"""
            <html>
            <body>
            <h1>Test Server</h1>
            <p>Your IP: {self.client_address[0]}</p>
            <p><a href="/ip">Get IP as text</a></p>
            </body>
            </html>
            """
            self.send_header("Content-length", len(response))
            self.end_headers()
            self.wfile.write(response.encode())


if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"Server running on port {PORT}")
        print(f"Test: curl http://localhost:{PORT}/ip")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("Server stopped")
