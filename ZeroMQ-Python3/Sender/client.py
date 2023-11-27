import zmq
import argparse
import sys
import os
import re
import time

# TODO move to another file
def check_file(file_name: str) -> int:
	# Check that the file to send is valid, will load into memory at last moment
	try :
		with open(file_name, "rb") as f:
			f.seek(0, os.SEEK_END)
			# get the size of the file in bytes
			size: int = f.tell()
			return size
			# file_data = f.read()
	except FileNotFoundError as e:
		sys.exit(f"usage: {sys.argv[0]} [-h] [-p P] -n N\n{sys.argv[0]}: error: argument -N: {file_name} does not exist.")


def extract_IP_subnet(network_interface: str) -> str:
	output = os.popen(f"ifconfig {network_interface}").read()
	pattern = r"\binet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b.*?\bnetmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
	match = re.search(pattern, output)
	if match:
		ip_address = match.group(1)
		subnet_mask = match.group(2)
	else:
		# TODO: change to an error
		sys.exit(f"usage: {sys.argv[0]} [-h] [-pw P] -fn N\n{sys.argv[0]}: error: {network_interface} is not setup properly")
	
	# Number of subnet bits
	num_subnet_bits  = str(bin(int(subnet_mask.split(".")[0])))[2:].count('1')
	num_subnet_bits += str(bin(int(subnet_mask.split(".")[1])))[2:].count('1')
	num_subnet_bits += str(bin(int(subnet_mask.split(".")[2])))[2:].count('1')
	num_subnet_bits += str(bin(int(subnet_mask.split(".")[3])))[2:].count('1')

	return f"{ip_address}/{num_subnet_bits}"

# Returns the binary version of the subnet portion of the IP adress that is correctly shifted
def getSubnetPortionBits(IP_subnet: str) -> bin:
	subnet_bits = int(IP_subnet.split("/")[0].split(".")[0])
	subnet_bits = subnet_bits << 8
	subnet_bits = subnet_bits | int(IP_subnet.split("/")[0].split(".")[1])
	subnet_bits = subnet_bits << 8
	subnet_bits = subnet_bits | int(IP_subnet.split("/")[0].split(".")[2])
	subnet_bits = subnet_bits << 8
	subnet_bits = subnet_bits | int(IP_subnet.split("/")[0].split(".")[3])

	subnet_bits = subnet_bits >> (32 - int(IP_subnet.split("/")[1]))
	subnet_bits = subnet_bits << (32 - int(IP_subnet.split("/")[1]))

	return subnet_bits

def getNumHostBits(IP_subnet: str) -> int:
	return 32 - int(IP_subnet.split("/")[1])

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

# # For use in a thread
# def IP_reach_out(ZMQ_addr: str, password: str) -> None:
# 	key = bytes(password, 'utf-8')
# 	# Filename, file size, file hash
# 	message = encyrpt(bytes("examplefilename.txt/int file size bytes/", 'utf-8'), key)

# 	global context
# 	socket = context.socket(zmq.REQ)
# 	socket.connect(ZMQ_addr)
# 	socket.send(message)

# 	time.sleep(1.0) #TODO: adjust

# 	# # Statistics
# 	# global num_reply
# 	# global num_valid_reply
# 	# # Recievers to send to
# 	# global recievers

# 	try:
# 		#  Get the reply.
# 		message = socket.recv(zmq.NOBLOCK)
# 		# num_reply += 1
# 		server_message = decyrpt(message, key)

# 		print(server_message)

# 		# if message == b"Hello Back": #TODO: adjust
# 		# 	num_valid_reply += 1
# 		# 	recievers[canidate_ip_addr] = message
# 	except zmq.error.Again as e:
# 		pass
# 	finally:
# 		socket.close()
# 		return None

# def send_file_data(ZMQ_addr: str, password: str) -> None:
# 	global file_data_bytes

# 	global context
# 	socket = context.socket(zmq.REQ)
# 	socket.connect(ZMQ_addr)

# 	socket.send(file_data_bytes)

# 	start_time: float = time.perf_counter()

# 	while (time.perf_counter() - start_time) < 4.0: #TODO Adjust
# 		try:
# 			#  Get the reply.
# 			message = socket.recv(zmq.NOBLOCK)

# 			if message == b"Hello Back": #TODO: adjust
# 				global num_file_sends
# 				num_file_sends += 1
# 			break

# 		except zmq.error.Again as e:
# 			time.sleep(1.0) #TODO Adjust

# 	socket.close()
# 	return None





# # Nessary Global Work for the ZMQ API
# import zmq
# context = zmq.Context()

# import argparse
# import sys
# import os
# import re

# import time
# # For testing
# def main():
# 	IP_reach_out("tcp://192.168.1.73:5556", "PLACE HOLDER")





# if __name__ == "__main__":
# 	main()