# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
# https://docs.python.org/3/library/http.server.html

# This server serves HTTP on port 1234. When it receives a WebSocket request, it completes
# the handshake and then blocks until it receives a payload, which should be
# "Hello Server!". It then sends a response payload consisting of "Hello Client!".

# Does not handle message fragmentation, ping/pong, binary data, extensions, subprotocols,
# multiple clients, or closing the connection.

import http.server
import socketserver
import hashlib
import base64

# Must be > 1023 if running as unprivileged user.
PORT = 1234

EXPECTED = "Hello Server!"
RESPONSE = "Hello Client!"


def get_accept(key: str) -> str:
	SALT = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	skey = key.encode("utf-8") + SALT
	digest = hashlib.sha1(skey).digest()
	return base64.b64encode(digest).decode("utf-8")
assert get_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

# Extract the n bits from the given byte starting at a0 and interpret as a binary number.
def bits(b, a0, n):
	return (b >> (8 - a0 - n)) & ((1 << n) - 1)
assert bits(42, 2, 4) == 10

def pullbytes(rfile, n):
	r = 0
	for b in rfile.read(n):
		r <<= 8
		r += b
	return r

def splitbits(b, *ns):
	for j, n in enumerate(ns):
		yield (b >> sum(ns[j+1:])) & ((1 << n) - 1)
assert list(splitbits(42, 2, 4, 2)) == [0, 10, 2]

def joinbits(*ans):
	r = 0
	for a, n in ans:
		r <<= n
		r += a
	return r
assert joinbits((0, 2), (10, 4), (2, 2)) == 42

# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
def extract_frame(rfile):
	b0 = pullbytes(rfile, 2)
	FIN, RSV, opcode, MASK, payload_len = splitbits(b0, 1, 3, 4, 1, 7)
	assert (FIN, RSV, opcode, MASK) == (1, 0, 1, 1)
	if payload_len == 126:
		payload_len = pullbytes(rfile, 2)
	elif payload_len == 127:
		payload_len = pullbytes(rfile, 4)
	print("extract_frame fields", FIN, RSV, opcode, MASK, payload_len)
	mask_key = [pullbytes(rfile, 1) for _ in range(4)]
	ENCODED = [pullbytes(rfile, 1) for _ in range(payload_len)]
	return "".join(chr(char ^ mask_key[j % 4]) for j, char in enumerate(ENCODED))

def encode_frame(text: str) -> bytes:
	frame = []
	FIN, RSV, opcode, MASK, payload_len = 1, 0, 1, 0, len(text)
	assert payload_len < 126
	frame.append(joinbits((FIN, 1), (RSV, 3), (opcode, 4)).to_bytes(1, "big"))
	frame.append(joinbits((MASK, 1), (payload_len, 7)).to_bytes(1, "big"))
	frame.append(text.encode("utf-8"))
	return b"".join(frame)



class Handler(http.server.BaseHTTPRequestHandler):
	def do_GET(self):
		print("***** GET HANDLER *****")
		print("client address:", self.client_address)
		print("command:", self.command)
		print("path:", self.path)
		print("request_version:", self.request_version)
		print("server_version:", self.server_version)
		print("sys_version:", self.sys_version)
		print("address_string:", self.address_string())
		for key, value in self.headers.items():
			print("header:", key, value)
		
		if "Sec-WebSocket-Version" not in self.headers:
			self.send_response(400, "Bad Request")
			return
			
		print("***** HANDSHAKE *****")
		self.send_response(101, "Switching Protocols")
		self.send_header("Upgrade", "websocket")
		self.send_header("Connection", "Upgrade")
		accept = get_accept(self.headers["Sec-WebSocket-Key"])
		print("accept:", accept)
		self.send_header("Sec-WebSocket-Accept", accept)
		self.end_headers()
		print("Handshake complete. Awaiting payload.")

		print("***** PAYLOAD *****")
		payload = extract_frame(self.rfile)
		print("Paylod received:", payload)
		assert payload == EXPECTED
		print("Sending response:", RESPONSE)
		self.wfile.write(encode_frame(RESPONSE))
		httpd.shutdown()
		

with socketserver.TCPServer(("", PORT), Handler) as httpd:
	print("serving at port", PORT)
	httpd.serve_forever()


