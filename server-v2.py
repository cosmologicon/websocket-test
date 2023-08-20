# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
# https://docs.python.org/3/library/http.server.html

# This server serves HTTP on port 1234. When it receives a WebSocket request, it completes
# the handshake and then blocks until it receives a payload. When the server receives a message
# frame, it responds with a message identifying the client and repeating the message back.
# If it receives the special message "CLOSE", or after receiving five messages from the same
# client, or if it receives a close frame, then the server sends a close frame and closes the
# connection.

# Does not handle message fragmentation, ping/pong, binary data, extensions, or subprotocols.

import http.server
import socketserver
import asyncio
import hashlib
import base64
from io import BytesIO

PORT = 1234
assert PORT > 1023  # Required if running as unprivileged user.


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

# Treats the number b as binary and splits it into separate binary numbers, each of which
# is n bits long, specified by ns.
# e.g. if b = 42 and ns = [2, 4, 2], then:
# 42 => 00101010b => 00,1010,10 => [00b, 1010b, 10b] => [0, 10, 2]
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



class ClientTracker:
	def __init__(self):
		self.nclient = 0
	def get_client_id(self):
		client_id = self.nclient
		self.nclient += 1
		return client_id
client_tracker = ClientTracker()


# Produces the Sec-WebSocket-Accept string for the Server handshake response.
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response
# key: the Sec-Websocket-Key provided by the client.
def get_accept(key: str) -> str:
	SALT = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	digest = hashlib.sha1(key.encode("utf-8") + SALT).digest()
	return base64.b64encode(digest).decode("utf-8")

# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
async def extract_frame(stream_reader):
	b0 = int.from_bytes(await stream_reader.read(2), "big")
	FIN, RSV, opcode, MASK, payload_len = splitbits(b0, 1, 3, 4, 1, 7)
	print("extract_frame", FIN, RSV, opcode, MASK, payload_len)
	# Not supported in this version:
	# FIN = 0 and opcode = 0: message fragmentation.
	# RSV > 0: extensions.
	# opcode = 2: binary data.
	# opcode = 9, 10: ping/pong.
	assert (FIN, RSV, MASK) == (1, 0, 1)
	assert opcode in [1, 8]
	is_close = opcode == 8
	if payload_len == 126:
		payload_len = int.from_bytes(await stream_reader.read(2), "big")
	elif payload_len == 127:
		payload_len = int.from_bytes(await stream_reader.read(8), "big")
	print("extract_frame fields", FIN, RSV, opcode, MASK, payload_len)
	mask_key = [int.from_bytes(await stream_reader.read(1), "big") for _ in range(4)]
	# Future improvement:
	# https://stackoverflow.com/questions/46540337/python-xoring-each-byte-in-bytes-in-the-most-efficient-way
	ENCODED = [int.from_bytes(await stream_reader.read(1), "big") for _ in range(payload_len)]
	payload = "".join(chr(char ^ mask_key[j % 4]) for j, char in enumerate(ENCODED))
	return is_close, payload

def encode_frame(text: str, opcode: int = 1) -> bytes:
	frame = []
	assert opcode in [1, 8]
	FIN, RSV, MASK, payload_len = 1, 0, 0, len(text)
	assert payload_len < 126
	frame.append(joinbits((FIN, 1), (RSV, 3), (opcode, 4)).to_bytes(1, "big"))
	frame.append(joinbits((MASK, 1), (payload_len, 7)).to_bytes(1, "big"))
	frame.append(text.encode("utf-8"))
	return b"".join(frame)

# We don't actually use the BaseHTTPRequestHandler class for anything except to parse the headers.
class HTTPRequestParser(http.server.BaseHTTPRequestHandler):
	def __init__(self, request_text):
		self.rfile = BytesIO(request_text)
		self.raw_requestline = self.rfile.readline()
		self.error_code = None
		self.error_message = None
		self.parse_request()

	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message

async def send_http(stream_writer, status_code, status_text, headers = ()):
	protocol_version = "HTTP/1.1"
	lines = [
		f"{protocol_version} {status_code} {status_text}",
	]
	for key, value in headers:
		lines.append(f"{key}: {value}")
	lines.append("")
	message = "".join(line + "\r\n" for line in lines).encode("utf-8")
	print("send_http", message)
	stream_writer.write(message)
	await stream_writer.drain()


async def handle_GET(client_id, request, stream_reader, stream_writer):
	print("***** GET HANDLER *****")
#	print("client address:", request.client_address)
	print("command:", request.command)
	print("path:", request.path)
	print("request_version:", request.request_version)
	print("server_version:", request.server_version)
	print("sys_version:", request.sys_version)
#	print("address_string:", request.address_string())
	for key, value in request.headers.items():
		print("header:", key, value)
	
	if "Sec-WebSocket-Version" not in request.headers:
		stream_writer.send_response(400, "Bad Request")
		return
		
	accept = get_accept(request.headers["Sec-WebSocket-Key"])
	print("accept:", accept)

	print("***** HANDSHAKE *****")
	headers = [
		("Upgrade", "websocket"),
		("Connection", "Upgrade"),
		("Sec-WebSocket-Accept", accept),
	]
	await send_http(stream_writer, 101, "Switching Protocols", headers)
	print("Handshake complete. Awaiting payload.")

	for nmessage in range(5):
		is_close, payload = await extract_frame(stream_reader)
		print("***** FRAME RECEIVED *****")
		print("Is close:", is_close)
		print("Payload:", payload)
		if is_close:
			break
		response = f"Client #{client_id} payload #{nmessage}: {payload}"
		print("Sending response:", response)
		stream_writer.write(encode_frame(response))
		await stream_writer.drain()
		if payload == "CLOSE":
			break
	print("SENDING CLOSE FRAME")
	print()
	stream_writer.write(encode_frame("", opcode = 8))
	await stream_writer.drain()
	stream_writer.close()
	await stream_writer.wait_closed()


async def handle(stream_reader, stream_writer):
	request_text = await stream_reader.readuntil(b"\r\n\r\n")
	request = HTTPRequestParser(request_text)
	await handle_GET(client_tracker.get_client_id(), request, stream_reader, stream_writer)

server = None
async def run_server():
	global server
	server = await asyncio.start_server(handle, host="", port=PORT)
	async with server:
		await server.serve_forever()
asyncio.run(run_server())

