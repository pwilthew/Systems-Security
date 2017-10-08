#!/usr/bin/python
#
# Python Web Server
# Serves only static files
#
# by Saumil Shah

import sys
import BaseHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

port = 8080

class HandlerClass(SimpleHTTPRequestHandler):
	# Disable DNS lookups
	def address_string(self):
		return str(self.client_address[0])

ServerClass = BaseHTTPServer.HTTPServer
Protocol = "HTTP/1.0"

server_address = ('0.0.0.0', port)

HandlerClass.protocol_version = Protocol
httpd = ServerClass(server_address, HandlerClass)

try:
	sa = httpd.socket.getsockname()
	print "Serving HTTP on", sa[0], "port", sa[1], "..."
	httpd.serve_forever()
except KeyboardInterrupt:
	print 'Shutting down the web server'
	httpd.socket.close()

