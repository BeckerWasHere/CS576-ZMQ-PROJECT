# Nessary Global Work for the ZMQ API
import zmq
context = zmq.Context()

import argparse
import sys
import os
import re

import time
import threading

from client import reach_out_to
from client import check_file
from client import getIp
from client import inspect_ethN_ip
from client import send_file
from client import IP_bloom

from crypto import encyrpt
from crypto import decyrpt

# Statistics to print
num_reply:       int = 0
num_valid_reply: int = 0
num_file_sends:  int = 0

# IPv4 -> password recieved
recievers dict[str, bytes] = dict()

# File Data to Send
# file_name: str
file_data_bytes: bytes

# Cyrpto
# password: bytes


def main():
	# Create a parser object
	# TODO make better -h help message
	parser = argparse.ArgumentParser(description="A simple program that takes two arguments")

	# Add the optional argument -n with a default value of 0
	parser.add_argument("-p", type=str, default=b"Detriot-Red", help="an optional binary argument")
	global password
	password = args.p

	# Add the mandatory argument -p
	parser.add_argument("-n", type=str, required=True, help="a mandatory string file name argument")

	# Parse the command line arguments
	args = parser.parse_args()

	check_file(args.n)
	
	# check that the host ip adress matches the eth0 or eth3 interface
	(network_portion_bin, num_hosts) = inspect_ethN_ip(0)

	encyrpt_file(args.n)

	exit()

	for ZMQ_addr in recievers_set:
		send_file(ZMQ_addr)

	# Print Stats
	

if __name__ == "__main__":
	main()
