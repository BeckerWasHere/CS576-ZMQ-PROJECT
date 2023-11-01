
from crypto import encyrpt
from crypto import decyrpt



def reach_out_to(canidate_ip_addr: str, file_name: str, password: str) -> None:

	# ZMQ functionality
	global context
	socket = context.socket(zmq.REQ)
	socket.connect(canidate_ip_addr)
	socket.send(
		encyrpt(
			bytes(file_name, 'utf-8'), 
			password
			)
		)

	time.sleep(1.0) #TODO: adjust

	# Statistics
	global num_reply
	global num_valid_reply
	# Recievers to send to
	global recievers

	try:
		#  Get the reply.
		message = socket.recv(zmq.NOBLOCK)
		num_reply += 1
		message = decyrpt(message, password)

		if message == b"Hello Back": #TODO: adjust
			num_valid_reply += 1
			recievers[canidate_ip_addr] = message
	except zmq.error.Again as e:
		pass
	finally:
		socket.close()
		return None

def check_file(file_name: str) -> None:
	# Check that the file to send is valid, will load into memory at last moment
	try :
		with open(file_name, "rb") as f:
			pass
			# file_data = f.read()
	except FileNotFoundError as e:
		sys.exit(f"usage: {sys.argv[0]} [-h] [-p P] -n N\n{sys.argv[0]}: error: argument -N: {file_name} does not exist.")

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

# Checks that the hostname corresponds to eth0
# Returns all possible ip adresses in the form of a net portion and the number of possible host portions
def inspect_ethN_ip(ethN: int) -> (bin, int):
	output = os.popen(f"ifconfig eth{ethN}").read()
	pattern = r"\binet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b.*?\bnetmask\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
	match = re.search(pattern, output)
	if match:
		ip_address = match.group(1)
		subnet_mask = match.group(2)
	else:
		# TODO: change to an error
		sys.exit(f"usage: {sys.argv[0]} [-h] [-pw P] -fn N\n{sys.argv[0]}: error: eth0 is not setup properly")

	# output = os.popen("hostname -I").read()
	# # output = "172.22.32.1 172.19.176.1 192.168.1.35 192.168.1.73 fd00:5cfa:25ea:c1fe:9427:7b02:f9ae:6ea5 2603:8000:3700:fbf9:731b:b1db:38fb:e2f5 2603:8000:3700:fbf9::1c96 2603:8000:3700:fbf9:4411:e2cf:fc2c:3737 2603:8000:3700:fbf9:a010:9147:c28b:afed fd00:5cfa:25ea:c1fe::1c96 fd00:5cfa:25ea:c1fe:4411:e2cf:fc2c:3737 fd00:5cfa:25ea:c1fe:a010:9147:c28b:afed"
	# pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
	# match = re.search(pattern, output)

	# if not match:
	# 	sys.exit(f"usage: {sys.argv[0]} [-h] [-p P] -n N\n{sys.argv[0]}: error: hostname -I command must work properly")
	# if match.group(1) != ip_address:
	# 	sys.exit(f"usage: {sys.argv[0]} [-h] [-p P] -n N\n{sys.argv[0]}: error: hostname must correspond to eth0 interface")


	# Network portion
	network_portion_bin = int(ip_address.split(".")[0]) & int(subnet_mask.split(".")[0])
	network_portion_bin = network_portion_bin << 8
	network_portion_bin = network_portion_bin | (int(ip_address.split(".")[1]) & int(subnet_mask.split(".")[1]))
	network_portion_bin = network_portion_bin << 8
	network_portion_bin = network_portion_bin | (int(ip_address.split(".")[2]) & int(subnet_mask.split(".")[2]))
	network_portion_bin = network_portion_bin << 8
	network_portion_bin = network_portion_bin | (int(ip_address.split(".")[3]) & int(subnet_mask.split(".")[3]))

	# Number of possible hosts in network
	num_hosts  = str(bin(int(subnet_mask.split(".")[0])))[2:].count('1')
	num_hosts += str(bin(int(subnet_mask.split(".")[1])))[2:].count('1')
	num_hosts += str(bin(int(subnet_mask.split(".")[2])))[2:].count('1')
	num_hosts += str(bin(int(subnet_mask.split(".")[3])))[2:].count('1')

	# Print Statistics
	print(f"IP address: {ip_address}/{num_hosts}")

	# Netmask bits to number of hosts
	num_hosts  = 2 ** (32 - num_hosts)

	return (network_portion_bin, num_hosts)


def get_ethN_names() -> list[str]:
	pass

def get_wifi_names() -> list[str]:
	pass

def get_subnet_portion(interface_name: str) -> bin:
	pass

def get_num_host_bits(interface_name: str) -> int:
	pass

def send_file_data(ZMQ_addr: str, password: str) -> None:
	global file_data_bytes

	global context
	socket = context.socket(zmq.REQ)
	socket.connect(ZMQ_addr)

	socket.send(file_data_bytes)

	start_time: float = time.perf_counter()

	while (time.perf_counter() - start_time) < 4.0: #TODO Adjust
		try:
			#  Get the reply.
			message = socket.recv(zmq.NOBLOCK)

			if message == b"Hello Back": #TODO: adjust
				global num_file_sends
				num_file_sends += 1
			break

		except zmq.error.Again as e:
			time.sleep(1.0) #TODO Adjust

	socket.close()
	return None

def IP_bloom(pswd: str) -> None:
	eth_num = 0
	pass