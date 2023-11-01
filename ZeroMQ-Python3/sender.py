import time
import zmq

import threading


context = zmq.Context()

def handhake_ip(ip_addr_str):
	socket = context.socket(zmq.REQ)
	socket.connect(ip_addr_str)
	print("here1")
	socket.send(b"Hello")
	print("here2")
	time.sleep(1.1)
	print("here3")
	try:
		#  Get the reply.
		print("here4")
		message = socket.recv(zmq.NOBLOCK)
		print("here5")
		if message != b"Hello Back":
			pass
		else:
			pass
	except zmq.error.Again as e:
		print("here6")
	print("here7")
	return

# def my_fun():
# 	ip_addr_str = "tcp://172.19.19.197:5555"

# 	socket = context.socket(zmq.REQ)
# 	socket.connect(ip_addr_str)
# 	print("here1")
# 	socket.send(b"Hello")
# 	print("here2")
# 	time.sleep(0.1)
# 	print("here3")
# 	try:
# 		#  Get the reply.
# 		print("here4")
# 		message = socket.recv(zmq.NOBLOCK)
# 		print("here5")
# 		if message != b"Hello Back":
# 			pass
# 		else:
# 			pass
# 	except zmq.error.Again as e:
# 		print("here6")

# 	print("here7")
# 	exit()
# 	print("here8")
		
# def my_fun2():
# 	# my_fun2()
# 	ip_addr_str = "tcp://172.19.19.197:5555"
# 	socket = context.socket(zmq.REQ)
# 	socket.connect(ip_addr_str)
# 	# print("here1")
# 	socket.send(b"Hello")
# 	# print("here2")
# 	# time.sleep(0.1)
# 	# print("here3")
# 	try:
# 		message = socket.recv(zmq.NOBLOCK)
# 	except zmq.error.Again as e:
# 		pass
# 	except NameError as e:
# 		pass
# 	return None

# print("got here")
# my_fun2()


if __name__ == '__main__':
	handhake_ip("tcp://172.19.19.197:5555")
	# my_fun2()
	# ip_addr_str = "tcp://172.19.19.197:5555"
	# context = zmq.Context()
	# socket = context.socket(zmq.REQ)
	# socket.connect(ip_addr_str)
	# # print("here1")
	# socket.send(b"Hello")
	# # print("here2")
	# # time.sleep(0.1)
	# # print("here3")
	# try:
	# 	message = socket.recv(zmq.NOBLOCK)
	# except zmq.error.Again as e:
	# 	pass
	# except NameError as e:
	# 	pass
	# socket.close()


	# handhake_ip("tcp://172.19.19.197:5555")
	# print("Ending")
	# exit()

	# thread_1 = threading.Thread(target=handhake_ip , name="Thread One", args=["tcp://172.19.19.197:5555"], daemon=False)

	# thread_1.start()
	# thread_1.join()
	# exit()