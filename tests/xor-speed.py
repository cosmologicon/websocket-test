# Figure out the most efficient way to xor the 4-bit mask with the encoded payload.
# https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#reading_and_unmasking_the_data
# https://stackoverflow.com/questions/46540337/python-xoring-each-byte-in-bytes-in-the-most-efficient-way

# Results: decode7 through decode10 are the fastest, basically indistinguishable
# https://docs.google.com/spreadsheets/d/1OyIxnN-nXVcjATAqTQhm1aB_XiufgNIYJGmvXsZ2Nps/edit?usp=sharing

import time, random, os, statistics, itertools, struct, array
from io import BytesIO


# Reference implementation.
def decode0(stream, payload_len, mask):
	mask_ints = list(mask)
	ret_bytes = []
	for j in range(payload_len):
		payload_byte = stream.read(1)
		payload_int = int.from_bytes(payload_byte, byteorder="big")
		mask_int = mask_ints[j % len(mask_ints)]
		ret_int = payload_int ^ mask_int
		ret_bytes.append(ret_int.to_bytes(length=1, byteorder="big"))
	return b"".join(ret_bytes)

# Single read.
def decode1(stream, payload_len, mask):
	mask_ints = list(mask)
	ret_bytes = []
	payload_bytes = stream.read(payload_len)
	for j in range(payload_len):
		mask_int = mask_ints[j % len(mask_ints)]
		ret_int = payload_bytes[j] ^ mask_int
		ret_bytes.append(ret_int.to_bytes(length=1, byteorder="big"))
	return b"".join(ret_bytes)

# Mask as bytes.
def decode2(stream, payload_len, mask):
	ret_bytes = []
	payload_bytes = stream.read(payload_len)
	for j in range(payload_len):
		mask_int = mask[j % len(mask)]
		ret_int = payload_bytes[j] ^ mask_int
		ret_bytes.append(ret_int.to_bytes(length=1, byteorder="big"))
	return b"".join(ret_bytes)

# Cycle mask.
def decode3(stream, payload_len, mask):
	ret_bytes = []
	payload_bytes = stream.read(payload_len)
	for payload_int, mask_int in zip(payload_bytes, itertools.cycle(mask)):
		ret_int = payload_int ^ mask_int
		ret_bytes.append(ret_int.to_bytes(length=1, byteorder="big"))
	return b"".join(ret_bytes)

# Gil Barash's solution using array
def decode4(stream, payload_len, mask):
	# Only works for mask_len = 4.
	mask_int = int.from_bytes(mask, "little")
	payload_bytes = stream.read(payload_len)
	if payload_len % 4 > 0:
		payload_bytes += b"\0" * (4 - payload_len % 4)
	arr = array.array("I", payload_bytes)
	for i in range(len(arr)):
		arr[i] ^= mask_int
	return bytes(arr)[:payload_len]

# Fabio Veronese's solution using an extended mask and single xor
# Fails sometimes, not sure why.
def decode5(stream, payload_len, mask):
	payload = stream.read(payload_len)
	payload_int = int.from_bytes(payload, byteorder='little', signed=False)
	mask_int = int.from_bytes(mask, byteorder='little', signed=False)
	mask_str = format(mask_int, '08x') * ((payload_int.bit_length() + 31) // 32)
	n = payload_int ^ int(mask_str, 16)
	return n.to_bytes(((n.bit_length() + 7) // 8), 'little')[:payload_len]

def decode6(stream, payload_len, mask):
	payload = stream.read(payload_len)
	payload_int = int.from_bytes(payload, byteorder='little')
	payload_len_4 = (payload_len + 3) // 4
	mask_extend = mask * payload_len_4
	mask_extend_int = int.from_bytes(mask_extend, byteorder='little')
	n = payload_int ^ mask_extend_int
	return n.to_bytes(payload_len_4 * 4, 'little')[:payload_len]

def decode7(stream, payload_len, mask):
	payload = stream.read(payload_len)
	payload_int = int.from_bytes(payload, byteorder='little')
	if payload_len % 4 > 0:
		extra = payload_len % 4
		mask_extend = mask * (payload_len // 4) + mask[:extra]
	else:
		mask_extend = mask * (payload_len // 4)
	mask_extend_int = int.from_bytes(mask_extend, byteorder='little')
	n = payload_int ^ mask_extend_int
	return n.to_bytes(payload_len, 'little')


def decode8(stream, payload_len, mask):
	payload = stream.read(payload_len)
	nreps, extra = divmod(payload_len, 4)
	mask = mask * nreps + mask[:extra] if extra else mask * nreps
	data_int = int.from_bytes(payload, byteorder="little")
	mask_int = int.from_bytes(mask, byteorder="little")
	return (data_int ^ mask_int).to_bytes(payload_len, 'little')

def decode9(stream, payload_len, mask):
	payload = stream.read(payload_len)
	nreps, extra = payload_len // 4, payload_len % 4
	mask = mask * nreps + mask[:extra] if extra else mask * nreps
	data_int = int.from_bytes(payload, byteorder="little")
	mask_int = int.from_bytes(mask, byteorder="little")
	return (data_int ^ mask_int).to_bytes(payload_len, 'little')

def decode10(stream, payload_len, mask):
	payload = stream.read(payload_len)
	nreps, extra = payload_len // 4, payload_len % 4
	mask = mask * nreps + mask[:extra]
	data_int = int.from_bytes(payload, byteorder="little")
	mask_int = int.from_bytes(mask, byteorder="little")
	return (data_int ^ mask_int).to_bytes(payload_len, 'little')

def shuffled(items):
	items = list(items)
	random.shuffle(items)
	return items

funcs = [
	("decode0", decode0),
	("decode1", decode1),
	("decode2", decode2),
	("decode3", decode3),
	("decode4", decode4),
#	("decode5", decode5),
	("decode6", decode6),
	("decode7", decode7),
	("decode8", decode8),
	("decode9", decode9),
	("decode10", decode10),
]
funcnames = [funcname for funcname, func in funcs]
def test(numtrials=100, payload_len=10, mask_len=4):
	times = { funcname: [] for funcname, func in funcs }
	for jtrial in range(numtrials):
		payload = os.urandom(payload_len)
		mask = os.urandom(mask_len)
		expected = decode0(BytesIO(payload), payload_len, mask)
		for funcname, func in shuffled(funcs):
			stream = BytesIO(payload)
			start = time.perf_counter()
			result = func(stream, payload_len, mask)
			stop = time.perf_counter()
			assert result == expected, f"{funcname} {payload} {mask}"
			ns_per_byte = 1e9 * (stop - start) / payload_len
			times[funcname].append(ns_per_byte)
	return times

NUM_TRIALS = 1000

payload_lens = [1, 2, 3, 5, 7, 10, 20, 30, 50, 70, 100, 300, 1000, 3000, 10000, 100000]
results = {}
for payload_len in payload_lens:
	for funcname, times in test(numtrials=NUM_TRIALS, payload_len=payload_len).items():
		results[(funcname, payload_len)] = times

metrics = [
	("MEAN", statistics.mean),
	("MEDIAN", statistics.median),
	("MAX", max),
	("STDEV", statistics.stdev),
	("99TH", lambda values: statistics.quantiles(values, n=100)[-1]),
]

for metric_name, metric in metrics:
	print(metric_name)
	print("payload len", *funcnames, sep="\t")
	for payload_len in payload_lens:
		fields = [payload_len]
		for funcname in funcnames:
			times = results[(funcname, payload_len)]
			fields.append(metric(times))
		print(*fields, sep="\t")
	print()

