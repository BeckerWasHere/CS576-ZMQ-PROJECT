# Nessary Global Work for the ZMQ API
import zmq
context = zmq.Context()

import argparse
import sys
import os
import subprocess
import re

import time
import threading

from client import check_file
from client import extract_IP_subnet
from client import getSubnetPortionBits
from client import getNumHostBits
from client import getIp


from security import symmetric_encrypt
from security import symmetric_decrypt
from security import asymmetric_encrypt

# Statistics to print
num_reply: int = 0
num_valid_reply: int = 0
num_file_sends: int = 0

# Cyrpto
symmetric_password: bytes

# IPv4 -> asymmetric_password recieved
recievers: dict([(str, bytes)]) = dict()

def inital_handshake(ZMQ_addr: str, message: bytes) -> None:
	global context
	socket = context.socket(zmq.REQ)
	socket.connect(ZMQ_addr)
	socket.send(message)

	time.sleep(0.1) #TODO: adjust

	# Statistics
	global num_reply
	global num_valid_reply
	# # Recievers to send to
	# global recievers

	try:
		#  Get the reply.
		server_message = socket.recv(zmq.NOBLOCK)
		num_reply += 1

		global symmetric_password
		server_message = str(symmetric_decrypt(server_message, symmetric_password), 'utf-8')
		print(f"reply = {server_message}")

		#TODO verify a signature

		# Expected Reply format: 
		# HELLO-BACK/PLACE_HOLDER_SIGNATURE/PUBLIC_KEY_STR_UTF-8
		if server_message.split("/./")[0] == "HELLO-BACK": #TODO: adjust
			num_valid_reply += 1
			global recievers
			recievers[ZMQ_addr] = bytes(server_message.split("/./")[2], 'utf-8')
	except zmq.error.Again as e:
		pass
	finally:
		socket.close()
		return None

def main() -> None:
	# Create a parser object
	# TODO make better -h help message
	parser = argparse.ArgumentParser(description="A simple program that sends a file to another IP on the network")

	# Add the optional argument -p
	parser.add_argument("-P", type=str, default=b"Detriot-Red", help="an optional argument using in the intial handshake")

	# Add the mandatory argument -n
	parser.add_argument("-N", type=str, required=True, help="a mandatory string file name argument")

	# Add the mandatory argument -i
	parser.add_argument("-I", type=str, required=True, help="a mandatory string network interface name")

	# Parse the command line arguments
	args = parser.parse_args()

	global symmetric_password
	symmetric_password = bytes(str(args.P), 'utf-8')

	# check that the file is okay to open, actual loading will be done last minute
	file_size: int = check_file(args.N)

	# check that the network interface passed in is valid
	try:
		subprocess.run(["ifconfig", args.I], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	except subprocess.CalledProcessError as e:
		print("Command failed with exit code", e.returncode)
		sys.exit(f"{args.I} is not a valid network interface")
	

	# Use the interface given to obtain the ip and mask
	interface_IP: str = extract_IP_subnet(args.I)

	file_name: str = args.N

	# Binary representation
	subnet_bits: bin = getSubnetPortionBits(interface_IP) 

	num_canidate_servers: int = 2 ** getNumHostBits(interface_IP)





	# Print Stats
	bloom_set = set()

	for host_bits in range(0, num_canidate_servers):
		ip_addr = "tcp://" + getIp(subnet_bits, host_bits) + ":5556"

		# TODO: impliment signature
		message: bytes = bytes(f"{interface_IP}/./{file_name}/./{file_size}/./PLACE_HOLDER_HASH_SIGNATURE", 'utf-8')

		# Encrypt message
		message = symmetric_encrypt(message, symmetric_password)

		thread = threading.Thread(target=inital_handshake , args=[ip_addr, message], daemon=False)
		bloom_set.add(thread)
		thread.start()

	for thread in bloom_set:
		thread.join()


	
	global num_reply
	global num_valid_reply

	print(f"number of replies: {num_reply}")
	print(f"number of valid replies: {num_valid_reply}")


	global recievers
	for ZMQ_addr in recievers:
		# File Data to Send
		file_data_bytes: bytes
		with open(file_name, "rb") as f:
			file_data_bytes = f.read()

		public_key: bytes = recievers[ZMQ_addr]
		file_data_bytes = asymmetric_encrypt(file_data_bytes, public_key)

		global context
		socket = context.socket(zmq.REQ)
		socket.connect(ZMQ_addr)
		socket.send(file_data_bytes)

		# final_message = socket.recv()
		# print(final_message)
		socket.close()
	

if __name__ == "__main__":
	main()