# from typing import Dict
import hashlib

# signature = hashlib.sha512()
# signature.update(bytes(27))

# # signature.digest()
# print(signature.hexdigest())


def sign(password: str, message_data: bytes) -> str:
	signature = hashlib.sha512()
	signature.update(bytes(password, 'utf-8'))
	signature.update(message_data)
	return signature.hexdigest()


def getMessage() -> bytes:
	password: str = "ghhghh"


	new_data: bytes = bytes("new text!!", 'utf-8')


	return bytes(
		sign(password, new_data) + "#" + str(new_data),
		'utf-8'
		)



message = getMessage()
# print(str(message, 'utf-8').split('#', 1)[0])
# print()
# print(str(message, 'utf-8').split('#', 1)[1])


recieved_signature = str(message, 'utf-8').split('#', 1)[0]

recieved_data = bytes(str(message, 'utf-8').split('#', 1)[1], 'utf-8'
# print(str(message, 'utf-8').split('#', 1)[0])
# print()
# print(str(message, 'utf-8').split('#', 1)[1])

correct_signature = sign("ghhghh", message.split(b'#')[1])
print(correct_signature)
print("recieved:")
print(recieved_signature)



# # signature.digest()
# print(correct_signature.hexdigest())
# print(recieved_signature)



# my_text: bytes = b"hello back#asdgsdbsdb"

# print(str(my_text, 'utf-8').split('#', 1)[1])

# my_dict: dict[str, bytes] = dict()
# my_dict = {
#     "key1": b"value1",
#     "key2": b"value2",
#     # ...
# }

# for (key, value) in my_dict.items():
# 	print(f"key: {key} = {value}")

# group.add("jeff")
# recievers["ghs"] = bytes("he", 'utf-8')
# from threading import Thread

# def foo(bar):
#     print('hello {}'.format(bar))
#     return 'foo'
    
# thread = Thread(target=foo, args=('world!',))
# thread.start()
# return_value = thread.join()
# print(return_value)

# A = [1,2,3]
# B = [3,4,5]

# print(A + B)


# name = "generic name"
# coding_scheme
# # print(str(bytes(name, 'utf-8'), 'utf-8'))
# print (type('utf-8'))

exit()

from my_lib import my_fuc
from my_lib import Pet
from my_lib import global_name


# my_fuc()
# my_pet = Pet()
# my_pet.pain()

def local_func():
	global global_name
	global_name += "h"


global global_name
print(global_name)
local_func()
print(global_name)


exit()


# import threading

# def thread_guy((data, other)) -> None:
# 	data += 1

# 	return None


# threads = set()

# data: int = 0

# for host in range(0, 10):
# 	thread = threading.Thread(target=thread_guy , args=[(data, None)], daemon=False)
# 	threads.add(thread)
# 	thread.start()

# for thread in threads:
# 	thread.join()

# print (data)

exit()



import zmq
context = zmq.Context()

import time
import threading

num_init = 0


def getIp(net: bin, host: bin) -> str:
	ip_bin = net | host
	ip_str = "." + str(int(ip_bin & 0xFF))
	ip_bin = ip_bin >> 8
	ip_str = "." + str(int(ip_bin & 0xFF)) + ip_str
	ip_bin = ip_bin >> 8
	ip_str = "." + str(int(ip_bin & 0xFF)) + ip_str
	ip_bin = ip_bin >> 8
	ip_str = str(int(ip_bin & 0xFF)) + ip_str
	return ip_str

def reach_out_to(canidate_ip_addr: str) -> None:
	global num_init
	num_init += 1

	socket = context.socket(zmq.REQ)
	socket.connect(canidate_ip_addr)
	socket.send(b"Hello") #TODO: adjust
	time.sleep(1.0) #TODO: adjust

	try:
		#  Get the reply.
		message = socket.recv(zmq.NOBLOCK)
		global num_reply
		num_reply += 1
		if message == b"Hello Back": #TODO: adjust
			global num_valid_reply
			num_valid_reply += 1
			pass
	except zmq.error.Again as e:
		pass
	finally:
		socket.close()
		return None

ip = "192.168.1.35"
netP = "172.19.184."

(num_reply, num_valid_reply) = (0, 0)

bloom_set = set()

for host in range(0, 256):
	ip_addr = "tcp://" + netP + str(host) + ":5555"
	thread = threading.Thread(target=reach_out_to , args=[ip_addr], daemon=False)
	bloom_set.add(thread)
	thread.start()

for thread in bloom_set:
	thread.join()

print (f"out of 256, {num_reply} replies, {num_valid_reply} are valid")
print (f"number initiated {num_init}")
exit()


import os
output = os.popen("ifconfig eth0").read()


import re
pattern = r"\binet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b.*?\bnetmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
match = re.search(pattern, output)
if match:
	ip_address = match.group(1)
	subnet_mask = match.group(2)
	print(f"IP address: {ip_address}")
	print(f"Subnet mask: {subnet_mask}")
else:
	print("No match found")

output = os.popen("hostname -I").read()
# output = "172.22.32.1 172.19.176.1 192.168.1.35 192.168.1.73 fd00:5cfa:25ea:c1fe:9427:7b02:f9ae:6ea5 2603:8000:3700:fbf9:731b:b1db:38fb:e2f5 2603:8000:3700:fbf9::1c96 2603:8000:3700:fbf9:4411:e2cf:fc2c:3737 2603:8000:3700:fbf9:a010:9147:c28b:afed fd00:5cfa:25ea:c1fe::1c96 fd00:5cfa:25ea:c1fe:4411:e2cf:fc2c:3737 fd00:5cfa:25ea:c1fe:a010:9147:c28b:afed"
pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
match = re.search(pattern, output)
print (match.group(1))
print (ip_address)

exit()

import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
password = b"password"
# salt = os.urandom(16)
pass_hash = hashlib.sha3_512()
pass_hash.update(password)
salt = pass_hash.digest()

kdf = PBKDF2HMAC(
	algorithm=hashes.SHA3_512(),
	length=32,
	salt=salt,
	iterations=480000, # affects performance
)
key = base64.urlsafe_b64encode(kdf.derive(password))
f = Fernet(key)

token = f.encrypt(b"Secret message!")
print(token)

print(f.decrypt(token))


# from cryptography.fernet import Fernet
# key = Fernet.generate_key() #this is your "password"
# # key = b"give me some sugar!"
# cipher_suite = Fernet(key)

# print(key)
# print(cipher_suite)

# encoded_text = cipher_suite.encrypt(b"Hello stackoverflow!")
# decoded_text = cipher_suite.decrypt(encoded_text)
# print(decoded_text)

exit()

import hashlib
import sys

# my_hash = hashlib.sha3_512()
# my_hash.update(b"Message A!")
# my_hash.update(b"Message B!")
# print(my_hash.hexdigest())

# new_hash = hashlib.sha3_512()
# new_hash.update(b"Message A!")
# other_hash = hashlib.sha3_512()
# other_hash = new_hash.digest()
# other_hash.update(b"Message B!")
# print(other_hash.hexdigest())

# A = hashlib.sha3_512().update(b"Message A!").hexdigest()

# B = hashlib.sha3_512().update(b"Message B!").hexdigest()


# combinedHashes = hashlib.sha3_512().update(A).update(B).hexdigest()
# print(combinedHashes)
# print(hashlib.sha3_512().update(b"Message A!").update(b"Message B!").hexdigest())

def encrypt():
	cypherChunk = hashlib.sha3_512()
	cypherChunk.update(b"Starting Point")

	# print(sys.getsizeof(cypherChunk.digest()))
	with open("Recording.mp4", "rb") as f:
		data = f.read()

	print(sys.getsizeof(data))

	pass

def decyrpt(data):
	pass


encrypt()
