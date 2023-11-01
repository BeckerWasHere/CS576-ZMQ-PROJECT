#
#   Hello World server in Python
#   Binds REP socket to tcp://*:5555
#   Expects b"Hello" from client, replies with b"World"
#

import time
import zmq

context = zmq.Context()
print()
socket = context.socket(zmq.REP)
# socket.bind("tcp://*:5555")
socket.bind("tcp://*:5555")
# socket.bind("tcp://172.25.197.45:5555")

while True:
    #  Wait for next request from client
    message = socket.recv()

    # with open("received.mp4", "wb") as f:
    #     f.write(message)

    print("Received request: %s" % message)

    #  Do some 'work'
    time.sleep(0.1)

    #  Send reply back to client
    socket.send(b"addadgf")