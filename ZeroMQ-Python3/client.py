#
#   Hello World client in Python
#   Connects REQ socket to tcp://localhost:5555
#   Sends "Hello" to server, expects "World" back

# https://zeromq.org/languages/python/
#
import time
import zmq

import os
output = os.popen("hostname -I").read()
addr = "tcp://" + output.strip() + ":5555"


# file_name = "Recording.mp4"


# # Read the file as binary data
# with open(file_name, "rb") as f:
#     data = f.read()
# # Send the data with a topic prefix
# context = zmq.Context()
# socket = context.socket(zmq.REQ)
# socket.connect("tcp://127.0.0.1:5555")
# socket.send(data)

context = zmq.Context()

#  Socket to talk to server
print("Connecting to hello world server…")
socket = context.socket(zmq.REQ)
# socket.connect("tcp://192.168.0.101:5555")
# socket.setsockopt(zmq.CONNECT_TIMEOUT, 1)
socket.connect("tcp://172.19.19.197:5555")
# socket.connect(addr)
socket.close()
socket = context.socket(zmq.REQ)
socket.connect(addr)

#  Do 10 requests, waiting each time for a response
for request in range(4):
    print("Sending request %s …" % request)
    socket.send(b"Hello")

    time.sleep(1.1)

    try:
        #  Get the reply.
        message = socket.recv(zmq.NOBLOCK)
        print("Received reply %s [ %s ]" % (request, message))
    except zmq.error.Again as e:
        print("Failed to recieve reply from server")
        exit()
