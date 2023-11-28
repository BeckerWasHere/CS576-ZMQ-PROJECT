# CS576-ZMQ-PROJECT

Usage is as follows

Sender Side:
python3 sender_outline.py -I [Interface Name, ex: eth0, wifi1] -N [file name]
or
python3 sender_outline.py -I [Interface Name, ex: eth0, wifi1] -N [file name] [-P] [Optional_Password_String]

Server Side:
python3 sender_outline.py [-P] [Optional_Password_String]


Known OS issues:
	1) port 5555 is used by the OS, port 5556 seems to work
	2) When the subnetmask is 255.255.240.0 = 0xFFFFF000, too many sockets are created and the program crashes dramatically. subnet 255.255.255.0 = 0xFFFFFF00 works just fine.
