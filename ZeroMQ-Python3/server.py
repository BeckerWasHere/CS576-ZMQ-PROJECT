#
#   Hello World server in Python
#   Binds REP socket to tcp://*:5555
#   Expects b"Hello" from client, replies with b"World"
#
import argparse
import time
import zmq

context = zmq.Context()

symmetric_password: bytes

import os
import hashlib


# TODO move to the shared folder
from Sender.security import symmetric_encrypt
from Sender.security import symmetric_decrypt
from Sender.security import get_public_key
from Sender.security import asymmetric_decrypt


def main() -> None:
	parser = argparse.ArgumentParser(description="A simple program that recieves a file from another IP on the network")

	# Add the optional argument -P
	parser.add_argument("-P", type=str, default=b"Detriot-Red", help="an optional argument using in the intial handshake")

	args = parser.parse_args()

	global symmetric_password
	symmetric_password = bytes(str(args.P), 'utf-8')

	global context
	socket = context.socket(zmq.REP)

	socket.bind("tcp://*:5556")


	#  Wait for next request from client
	print("Waiting for sender ...")
	handshake_message = symmetric_decrypt(socket.recv(), symmetric_password)


	print("Received initial contact message")

	file_name: str = str(handshake_message, 'utf-8').split("/./")[1]
	file_size_bytes: int = str(handshake_message, 'utf-8').split("/./")[2]
	print(f"Incoming file name: {file_name}, size: {file_size_bytes} bytes")

	print("Sending public key to Sender")
	# Expected Reply format: 
	# HELLO-BACK/PLACE_HOLDER_SIGNATURE/PUBLIC_KEY_STR_UTF-8

	# key -> str(key, utf-8) -> symmetric_encrypt(bytes()) -> symmetric_decrypt -> str() -> bytes
	new_key: bytes = get_public_key()
	reply_message: str = "HELLO-BACK/./PLACE_HOLDER_SIGNATURE" + "/./" + str(new_key, 'utf-8')
	socket.send(symmetric_encrypt(bytes(reply_message, 'utf-8'), symmetric_password))

	print("Waiting on file")
	file_data: bytes = asymmetric_decrypt(socket.recv())
	with open(file_name, "wb") as f:
		f.write(file_data)


if __name__ == "__main__":
	main()
