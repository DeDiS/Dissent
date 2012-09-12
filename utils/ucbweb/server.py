"""
Server for UCB test tracefiles

Server responds to GET requests of the form:
GET /ignored-string?HEADLEN&BODYLEN

The server returns a random string of length
HEADLEN+BODYLEN to the client and closes the
connection.
"""

import BaseHTTPServer
import os
import string

LISTEN_IP = "10.0.0.13"
LISTEN_PORT = 9090

class TraceHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  def do_GET(self):
    self.send_response(200)
    
    url,rest = self.path.split('?')
    len_headers,len_body = rest.split('&')

    self.end_headers()
    self.wfile.write(os.urandom(int(len_headers)))
    self.wfile.write(os.urandom(int(len_body)))

    return

def main():
  server_address = (LISTEN_IP, LISTEN_PORT)
  httpd = BaseHTTPServer.HTTPServer(server_address, TraceHandler)
  httpd.serve_forever()

if __name__ == "__main__":
  main()


