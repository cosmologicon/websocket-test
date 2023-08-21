# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
# https://docs.python.org/3/library/http.server.html

# This server serves HTTP on port 23400. When it receives a WebSocket request, it completes
# the handshake and then asynchronously awaits a payload. When the server receives a message
# frame, it responds with a message identifying the client and repeating the message back.
# If it receives the special message "CLOSE", or after receiving five messages from the same
# client, or if it receives a close frame, then the server sends a close frame and closes the
# connection.

# Does not handle message fragmentation, ping/pong, extensions, or subprotocols.

import http.server
import socketserver
import asyncio
import hashlib
import base64
from itertools import count
from io import BytesIO

PORT = 23400
assert PORT > 1023  # Required if running as unprivileged user.


### WEBSOCKET UTILITY FUNCTIONS ###

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

# Produces the Sec-WebSocket-Accept string for the Server handshake response.
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#server_handshake_response
# key: the Sec-Websocket-Key provided by the client.
def get_accept(key: str) -> str:
	SALT = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	digest = hashlib.sha1(key.encode("utf-8") + SALT).digest()
	return base64.b64encode(digest).decode("utf-8")

async def read_int(stream_reader, nbytes):
	return int.from_bytes(await stream_reader.read(nbytes), "big")

def trunc(message, max_len = 50):
	if len(message) <= max_len:
		return message
	return f"{message[:max_len-6]}... [{len(message)}]"


# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#format
# Not supported in this version:
# RSV > 0: extensions.
# opcode = 9, 10: ping/pong.
class Frame:
	async def build(self, stream_reader):
		b0 = await read_int(stream_reader, 2)
		self.FIN, self.RSV, self.opcode, self.MASK, payload_len = splitbits(b0, 1, 3, 4, 1, 7)
		assert self.RSV == 0
		assert self.MASK == 1
		assert self.opcode in [0, 1, 2, 8]
		self.is_continuation = self.opcode == 0
		self.is_text = self.opcode == 1
		self.is_binary = self.opcode == 2
		self.is_close = self.opcode == 8
		self.is_final = self.FIN == 1

		if payload_len == 126:
			payload_len = await read_int(stream_reader, 2)
		elif payload_len == 127:
			payload_len = await read_int(stream_reader, 8)
		mask_key = [await read_int(stream_reader, 1) for _ in range(4)]
		# Future improvement:
		# https://stackoverflow.com/questions/46540337/python-xoring-each-byte-in-bytes-in-the-most-efficient-way
		encoded = [await read_int(stream_reader, 1) for _ in range(payload_len)]
		self.payload = "".join(chr(char ^ mask_key[j % 4]) for j, char in enumerate(encoded))

	def __repr__(self):
		fields = [
			f"FIN={self.FIN}",
			f"opcode={self.opcode}",
			f'payload="{trunc(self.payload, 20)}"',
		]
		return f"FRAME<{', '.join(fields)}>"

	@classmethod
	async def read(cls, reader):
		frame = Frame()
		await frame.build(reader)
		return frame


def join_payload(frames):
	assert len(frames) > 0
	assert frames[0].is_text or frames[0].is_binary
	assert all(frame.is_continuation for frame in frames[1:])
	assert frames[-1].is_final
	assert all(not frame.is_final for frame in frames[:-1])
	return "".join(frame.payload for frame in frames)


def encode_frame(text: str, FIN: int = 1, opcode: int = 1) -> bytes:
	frame = []
	assert opcode in [0, 1, 8]
	RSV, MASK, payload_len = 0, 0, len(text)
	frame.append(joinbits((FIN, 1), (RSV, 3), (opcode, 4)).to_bytes(1, "big"))
	if payload_len < 126:
		pass
	elif payload_len < 2 ** 16:
		payload_len = 126
	elif payload_len < 2 ** 64:
		payload_len = 127
	else:
		raise ValueError("payload too big somehow")
	frame.append(joinbits((MASK, 1), (payload_len, 7)).to_bytes(1, "big"))
	if payload_len == 126:
		frame.append(len(text).to_bytes(2, "big"))
	if payload_len == 127:
		frame.append(len(text).to_bytes(8, "big"))
	frame.append(text.encode("utf-8"))
	return b"".join(frame)


### SERVER AND HANDLER CODE ###

# We only use the BaseHTTPRequestHandler class for parsing the HTTP headers.
# https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class HTTPRequestParser(http.server.BaseHTTPRequestHandler):
	def __init__(self, request_text):
		self.rfile = BytesIO(request_text)
		self.raw_requestline = self.rfile.readline()
		self.error_code = None
		self.error_message = None
		self.parse_request()

	def dump_info(self):
		print("command:", self.command)
		print("path:", self.path)
		print("request_version:", self.request_version)
		print("server_version:", self.server_version)
		print("sys_version:", self.sys_version)
		for key, value in self.headers.items():
			print("header:", key, value)

	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message

# Main asynchronous WebSocket handler. Is created for each initial request. If the handshake
# succeeds, it remains open until either it receives a close frame, or self.running is set to
# False.
class Handler:
	client_counter = count()
	max_payload_len = 100000

	def __init__(self, stream_reader, stream_writer):
		self.reader = stream_reader
		self.writer = stream_writer
		self.client_id = next(self.client_counter)
		self.nmessage = 0
		self.running = True

	async def send(self, message: bytes):
		self.writer.write(message)
		await self.writer.drain()

	async def send_http(self, status_code, status_text, headers = ()):
		protocol_version = "HTTP/1.1"
		lines = [
			f"{protocol_version} {status_code} {status_text}",
		]
		for key, value in headers:
			lines.append(f"{key}: {value}")
		lines.append("")
		await self.send("".join(line + "\r\n" for line in lines).encode("utf-8"))

	async def send_message(self, message: str):
		P = self.max_payload_len
		npart = len(message) // P + 1
		for j in range(npart):
			part = message[j * P: (j+1) * P]
			FIN = j == npart - 1
			opcode = 1 if j == 0 else 0
			await self.send(encode_frame(part, FIN = FIN, opcode = opcode))

	async def close_writer(self):
		self.writer.close()
		await self.writer.wait_closed()

	async def close(self):
		print("SENDING CLOSE FRAME")
		print()
		await self.send(encode_frame("", opcode = 8))
		await self.close_writer()

	async def handshake(self):
		request_text = await self.reader.readuntil(b"\r\n\r\n")
		self.request = HTTPRequestParser(request_text)
		if "Sec-WebSocket-Version" not in self.request.headers:
			await send_http(stream_writer, 400, "Bad Request")
			await self.close_writer()
		accept = get_accept(self.request.headers["Sec-WebSocket-Key"])
		headers = [
			("Upgrade", "websocket"),
			("Connection", "Upgrade"),
			("Sec-WebSocket-Accept", accept),
		]
		await self.send_http(101, "Switching Protocols", headers)

	async def run(self):
		frames = []
		while self.running:
			frame = await Frame.read(self.reader)
			print("RECEIVED", frame)
			if frame.is_close:
				self.running = False
				break
			frames.append(frame)
			if not frame.is_final:
				continue
			message = join_payload(frames)
			if frames[0].is_text:
				ret = await self.on_text(message)
			elif frames[0].is_binary:
				ret = await self.on_binary(message)
			if ret is False:
				self.running = False
			frames = []

	async def on_binary(self, message):
		return await self.on_text(message)	

	async def on_text(self, message):
		response = f"Client #{self.client_id} payload #{self.nmessage}: {message}"
		self.nmessage += 1
		print("Sending response:", trunc(response))
		await self.send_message(response)
		if message == "CLOSE" or self.nmessage == 5:
			return False

async def handle(stream_reader, stream_writer):
	handler = Handler(stream_reader, stream_writer)
	await handler.handshake()
	await handler.run()
	await handler.close()


async def run_server():
	server = await asyncio.start_server(handle, host="", port=PORT)
	async with server:
		await server.serve_forever()
asyncio.run(run_server(), debug = True)

